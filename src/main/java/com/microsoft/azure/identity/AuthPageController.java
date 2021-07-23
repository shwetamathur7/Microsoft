// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package com.microsoft.azure.identity;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.text.ParseException;
import java.util.UUID;
import java.util.concurrent.ExecutionException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.microsoft.aad.msal4j.*;
import com.nimbusds.jwt.JWTParser;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.ModelAndView;


@Controller
public class AuthPageController {

    @Autowired
    AuthHelper authHelper;

    @RequestMapping("/identity")
    public String homepage(){
        return "index";
    }

    @RequestMapping("/identity/secure/aad")
    public ModelAndView securePage(HttpServletRequest httpRequest) throws ParseException {
        ModelAndView mav = new ModelAndView("auth_page");

        setAccountInfo(mav, httpRequest);

        return mav;
    }

    @RequestMapping("/identity/sign_out")
    public void signOut(HttpServletRequest httpRequest, HttpServletResponse response) throws IOException {

        httpRequest.getSession().invalidate();

        String endSessionEndpoint = "https://login.microsoftonline.com/common/oauth2/v2.0/logout";

        String redirectUrl = "https://localhost:8443/identity/";
        response.sendRedirect(endSessionEndpoint + "?post_logout_redirect_uri=" +
                URLEncoder.encode(redirectUrl, "UTF-8"));
    }
    @RequestMapping("/client_api")
    public ModelAndView callClientApi(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws Exception {

        ModelAndView mav = new ModelAndView("auth_page");
        String clientApiCallResult = null;
        try {
            setAccountInfo(mav, httpRequest);

            IAuthenticationResult result = authHelper.getAuthResultBySilentFlow(httpRequest, authHelper.configuration.clientDefaultScope);
            clientApiCallResult = callClientService(result.accessToken());
        } catch (Exception ex) {
            authHelper.removePrincipalFromSession(httpRequest);
            httpResponse.setStatus(500);
            httpRequest.setAttribute("error", ex.getMessage());
            httpRequest.getRequestDispatcher("/error").forward(httpRequest, httpResponse);
        }

        mav.addObject("client_api_call_res", clientApiCallResult);
        return mav;
    }


    @RequestMapping("/identity/graph/me")
    public ModelAndView getUserFromGraph(HttpServletRequest httpRequest, HttpServletResponse httpResponse,String scope)
            throws Throwable {

        IAuthenticationResult result;
        ModelAndView mav;
        try {
            result = authHelper.getAuthResultBySilentFlow(httpRequest, httpResponse);
        } catch (ExecutionException e) {
            if (e.getCause() instanceof MsalInteractionRequiredException) {

                // If silent call returns MsalInteractionRequired, then redirect to Authorization endpoint
                // so user can consent to new scopes
                String state = UUID.randomUUID().toString();
                String nonce = UUID.randomUUID().toString();

                SessionManagementHelper.storeStateAndNonceInSession(httpRequest.getSession(), state, nonce);
                String authorizationCodeUrl = authHelper.getAuthorizationCodeUrl(
                        httpRequest.getParameter("claims"),
                        "User.Read",
                        authHelper.getRedirectUriGraph(),
                        state,
                        nonce);

                return new ModelAndView("redirect:" + authorizationCodeUrl);
            } else {

                mav = new ModelAndView("error");
                mav.addObject("error", e);
                return mav;
            }
        }

        if (result == null) {
            mav = new ModelAndView("error");
            mav.addObject("error", new Exception("AuthenticationResult not found in session."));
        } else {
            mav = new ModelAndView("auth_page");
            setAccountInfo(mav, httpRequest);

            try {
                getUserInfoFromGraph(mav, result.accessToken());

                return mav;
            } catch (Exception e) {
                mav = new ModelAndView("error");
                mav.addObject("error", e);
            }
        }
        return mav;
    }

    private void getUserInfoFromGraph(ModelAndView mav,String accessToken) throws Exception {
        // Microsoft Graph user endpoint
        URL url = new URL(authHelper.getMsGraphEndpointHost() + "v1.0/me");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();

        // Set the appropriate header fields in the request header.
        conn.setRequestProperty("Authorization", "Bearer " + accessToken);
        conn.setRequestProperty("Accept", "application/json");

        String response = HttpClientHelper.getResponseStringFromConn(conn);

        int responseCode = conn.getResponseCode();
        if(responseCode != HttpURLConnection.HTTP_OK) {
            throw new IOException(response);
        }

        JSONObject responseObject = HttpClientHelper.processResponse(responseCode, response);
        mav.addObject("userInfo", responseObject.getJSONObject("responseMsg").toString());
        mav.addObject("displayName", responseObject.getJSONObject("responseMsg").getString("displayName"));
        mav.addObject("mail", responseObject.getJSONObject("responseMsg").getString("mail"));
        mav.addObject("jobTitle", responseObject.getJSONObject("responseMsg").getString("jobTitle"));
        mav.addObject("userPrincipalName", responseObject.getJSONObject("responseMsg").getString("userPrincipalName"));


    }

    private void setAccountInfo(ModelAndView model, HttpServletRequest httpRequest) throws ParseException {
        IAuthenticationResult auth = SessionManagementHelper.getAuthSessionObject(httpRequest);

        String tenantId = JWTParser.parse(auth.idToken()).getJWTClaimsSet().getStringClaim("tid");

        model.addObject("tenantId", tenantId);
        model.addObject("account", SessionManagementHelper.getAuthSessionObject(httpRequest).account());
    }
    private String callClientService(String accessToken) {
        RestTemplate restTemplate = new RestTemplate();

        org.springframework.http.HttpHeaders headers = new org.springframework.http.HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Authorization", "Bearer " + accessToken);
        HttpEntity<String> entity = new HttpEntity<>(null, headers);

        return restTemplate.exchange("http://localhost:8081/get", HttpMethod.GET,
                entity, String.class).getBody();
    }
}
