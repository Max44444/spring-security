package com.binarystudio.academy.springsecurity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties
public class SpringSecurityTutorialApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityTutorialApplication.class, args);
	}

}
