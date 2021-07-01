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
		// Here we store the cookie with the redirect uri which we got from client,
		// so that further we can pass him the JWT back
		var redirectUri = request.getParameter(REDIRECT_URI_PARAM);
		if (StringUtils.hasText(redirectUri)) {
			Cookie redirCookie = new Cookie(REDIRECT_URI_PARAM, redirectUri);
			redirCookie.setPath("/");
			redirCookie.setHttpOnly(true);
			// we can extract cookie's max age to application.yml
			redirCookie.setMaxAge(180);
			response.addCookie(redirCookie);
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
