package com.binarystudio.academy.springsecurity.domain.user;

import com.binarystudio.academy.springsecurity.domain.user.model.User;
import com.binarystudio.academy.springsecurity.domain.user.model.UserRole;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.*;

@Repository
public class UserRepository {

	private final List<User> users = new ArrayList<>();

	public UserRepository(PasswordEncoder passwordEncoder) {
		var regularUser = new User();
		regularUser.setUsername("regular");
		regularUser.setEmail("regular@mail.com");
		regularUser.setId(UUID.fromString("dcdd7e97-8ba4-4cef-8212-1c2e1f3c529b"));
		regularUser.setPassword(passwordEncoder.encode("password"));
		regularUser.setAuthorities(Set.of(UserRole.USER));
		this.users.add(regularUser);

		var adminUser = new User();
		adminUser.setUsername("privileged");
		adminUser.setEmail("privileged@mail.com");
		adminUser.setId(UUID.randomUUID());
		adminUser.setPassword(passwordEncoder.encode("password"));
		adminUser.setAuthorities(Set.of(UserRole.ADMIN));
		this.users.add(adminUser);

	}

	public Optional<User> findByUsername(String username) {
		return users.stream()
				.filter(user -> user.getUsername().equals(username))
				.findAny();
	}

	public Optional<User> findByEmail(String email) {
		return users.stream()
				.filter(user -> user.getEmail().equals(email))
				.findAny();
	}

	public List<User> findUsers() {
		return Collections.unmodifiableList(users);
	}

	public void createUserByEmail(String email) {
		var createdUser = new User();
		createdUser.setEmail(email);
		createdUser.setUsername(email);
		createdUser.setAuthorities(Set.of(UserRole.USER));
		users.add(createdUser);
	}

	public User createUser(String login, String email, String password) {
		var createdUser = new User();
		createdUser.setId(UUID.randomUUID());
		createdUser.setEmail(email);
		createdUser.setUsername(login);
		createdUser.setPassword(password);
		createdUser.setAuthorities(Set.of(UserRole.USER));
		users.add(createdUser);
		return createdUser;
	}

	public User changeUserPassword(User user, String newPassword) {
		var currentUser = findByEmail(user.getEmail()).orElseThrow();
		var idx = users.indexOf(currentUser);
		currentUser.setPassword(newPassword);
		return users.set(idx, currentUser);
	}
}
