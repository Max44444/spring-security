package com.binarystudio.academy.springsecurity.security.auth;

import com.binarystudio.academy.springsecurity.domain.user.model.User;
import com.binarystudio.academy.springsecurity.security.auth.model.*;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("auth")
public class AuthController {
	private final AuthService authService;

	public AuthController(AuthService authService) {
		this.authService = authService;
	}

	@PostMapping("safe/login")
	public AuthResponse login(@RequestBody AuthorizationRequest authorizationRequest) {
		return authService.performLogin(authorizationRequest);
	}

	@PostMapping("safe/register")
	public AuthResponse register(@RequestBody RegistrationRequest registrationRequest) {
		// 1. todo: implement registration
		return null;
	}

	@PostMapping("safe/refresh")
	public AuthResponse refreshTokenPair(@RequestBody RefreshTokenRequest refreshTokenRequest) {
		// 2. todo: implement refresh token
		return null;
	}

	@PutMapping("safe/forgotten_password")
	public void forgotPasswordRequest(@RequestParam String email) {
		// 6. todo: implement token display for further password update
	}

	@PatchMapping("safe/forgotten_password")
	public AuthResponse forgottenPasswordReplacement(@RequestBody ForgottenPasswordReplacementRequest forgottenPasswordReplacementRequest) {
		// 6. todo: implement password replacement and returning tokens
		return null;
	}

	@PatchMapping("change_password")
	public AuthResponse changePassword(@RequestBody PasswordChangeRequest passwordChangeRequest) {
		// 5. todo: implement password changing
		return null;
	}

	@GetMapping("me")
	public User whoAmI(@AuthenticationPrincipal User user) {
		return user;
	}
}
