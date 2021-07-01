package com.binarystudio.academy.springsecurity.security.auth;

import com.binarystudio.academy.springsecurity.domain.user.UserService;
import com.binarystudio.academy.springsecurity.security.auth.model.AuthResponse;
import com.binarystudio.academy.springsecurity.security.auth.model.AuthorizationRequest;
import com.binarystudio.academy.springsecurity.security.jwt.JwtProvider;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class AuthService {
	private final UserService userService;
	private final JwtProvider jwtProvider;
	private final PasswordEncoder passwordEncoder;

	public AuthService(UserService userService, JwtProvider jwtProvider, PasswordEncoder passwordEncoder) {
		this.userService = userService;
		this.jwtProvider = jwtProvider;
		this.passwordEncoder = passwordEncoder;
	}

	public AuthResponse performLogin(AuthorizationRequest authorizationRequest) {
		var userDetails = userService.loadUserByUsername(authorizationRequest.getUsername());
		if (passwordsDontMatch(authorizationRequest.getPassword(), userDetails.getPassword())) {
			throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid password");
		}
		// 2. todo: auth and refresh token are given to user
		return AuthResponse.of(jwtProvider.generateToken(userDetails));
	}

	private boolean passwordsDontMatch(String rawPw, String encodedPw) {
		return !passwordEncoder.matches(rawPw, encodedPw);
	}

}
