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
        return authService.performRegistration(registrationRequest);
    }

    @PostMapping("safe/refresh")
    public AuthResponse refreshTokenPair(@RequestBody RefreshTokenRequest refreshTokenRequest) {
        return authService.performRefreshTokenPair(refreshTokenRequest);
    }

    @PutMapping("safe/forgotten_password")
    public void forgotPasswordRequest(@RequestParam String email) {
        authService.performGenerateTokenForUpdatingPassword(email);
    }

    @PatchMapping("safe/forgotten_password")
    public AuthResponse forgottenPasswordReplacement(@RequestBody ForgottenPasswordReplacementRequest forgottenPasswordReplacementRequest) {
        return authService.performPasswordReplacement(forgottenPasswordReplacementRequest);
    }

    @PatchMapping("change_password")
    public AuthResponse changePassword(
            @RequestBody PasswordChangeRequest passwordChangeRequest,
            @AuthenticationPrincipal User user
    ) {
        return authService.performChangingPassword(user, passwordChangeRequest);
    }

    @GetMapping("me")
    public User whoAmI(@AuthenticationPrincipal User user) {
        return user;
    }

}
