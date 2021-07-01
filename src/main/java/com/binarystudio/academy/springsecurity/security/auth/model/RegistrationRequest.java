package com.binarystudio.academy.springsecurity.security.auth.model;

import lombok.Data;

@Data
public class RegistrationRequest {
	private String email;
	private String login;
	private String password;
}
