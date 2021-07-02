package com.binarystudio.academy.springsecurity.security.auth.model;

import lombok.Data;

@Data
public class ForgottenPasswordReplacementRequest {

    private String token;
    private String newPassword;

}
