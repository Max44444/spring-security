package com.binarystudio.academy.springsecurity.security.auth.model;

import lombok.Data;

@Data
public class AuthResponse {

    private String accessToken;
    private String refreshToken;

    public static AuthResponse of(String accessToken, String refreshToken) {
        var response = new AuthResponse();
        response.setAccessToken(accessToken);
        response.setRefreshToken(refreshToken);
        return response;
    }

}
