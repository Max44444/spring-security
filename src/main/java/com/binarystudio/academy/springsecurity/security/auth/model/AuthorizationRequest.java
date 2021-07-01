package com.binarystudio.academy.springsecurity.security.auth.model;

import lombok.Data;

@Data
public class AuthorizationRequest {
	private String username;
	private String password;
}
