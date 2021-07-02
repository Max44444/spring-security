package com.binarystudio.academy.springsecurity.security.oauth2;

import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.util.StringUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class RedirectUriToCookiePersister implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {

    public static final String REDIRECT_URI_PARAM = "redirect_uri";
    private final HttpSessionOAuth2AuthorizationRequestRepository httpSessionRepository = new HttpSessionOAuth2AuthorizationRequestRepository();

    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        return httpSessionRepository.loadAuthorizationRequest(request);
    }

    @Override
    public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request, HttpServletResponse response) {
        var redirectUri = request.getParameter(REDIRECT_URI_PARAM);
        if (StringUtils.hasText(redirectUri)) {
            var redirectCookie = new Cookie(REDIRECT_URI_PARAM, redirectUri);
            redirectCookie.setPath("/");
            redirectCookie.setHttpOnly(true);
            redirectCookie.setMaxAge(180);
            response.addCookie(redirectCookie);
        }
        httpSessionRepository.saveAuthorizationRequest(authorizationRequest, request, response);
    }

    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request) {
        return httpSessionRepository.removeAuthorizationRequest(request);
    }

    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request, HttpServletResponse response) {
        return httpSessionRepository.removeAuthorizationRequest(request, response);
    }

}
