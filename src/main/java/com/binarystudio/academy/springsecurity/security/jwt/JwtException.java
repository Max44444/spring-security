package com.binarystudio.academy.springsecurity.security.jwt;

import lombok.Getter;

@Getter
public class JwtException extends RuntimeException {
	private final String code;

	public JwtException(String message, String code) {
		super(message);
		this.code = code;
	}
}
