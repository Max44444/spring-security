package com.binarystudio.academy.springsecurity.security.auth.model;

import lombok.Data;

@Data
public class RefreshTokenRequest {
	private String refreshToken;
}
