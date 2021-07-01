package com.binarystudio.academy.springsecurity;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import javax.crypto.SecretKey;

@SpringBootTest
class SpringSecurityTutorialApplicationTests {

	@Test
	void contextLoads() {
	}

	@Test
	void generateSecretKey() {
		SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS512);
		String base64Key = Encoders.BASE64.encode(key.getEncoded());
		System.out.println(base64Key);
	}
}
