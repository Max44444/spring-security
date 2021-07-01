package com.binarystudio.academy.springsecurity.domain.user.model;

import lombok.Data;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Set;
import java.util.UUID;

@Data
public class User implements UserDetails {
	private UUID id;
	private String username;
	private String email;
	private String password;
	private Set<UserRole> authorities;

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}
}
