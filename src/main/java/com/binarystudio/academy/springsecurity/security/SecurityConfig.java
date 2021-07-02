package com.binarystudio.academy.springsecurity.security;

import com.binarystudio.academy.springsecurity.domain.user.model.UserRole;
import com.binarystudio.academy.springsecurity.security.jwt.JwtFilter;
import com.binarystudio.academy.springsecurity.security.oauth2.RedirectUriToCookiePersister;
import com.binarystudio.academy.springsecurity.security.oauth2.SimpleOAuth2SuccessHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	private void applyRouteRestrictions(HttpSecurity http) throws Exception {
		http
				.authorizeRequests()
				.antMatchers("/auth/**").permitAll()
				.antMatchers(HttpMethod.GET, "/hotels/*").permitAll()
				.antMatchers("/hotels/**").hasAnyRole(UserRole.ADMIN.toString(), UserRole.USER.toString())
				.antMatchers("/users/all").hasRole(UserRole.ADMIN.toString())
				.antMatchers("/actuator/**").hasRole(UserRole.ADMIN.toString())
				.anyRequest().authenticated();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
				.cors().and()
				.csrf().disable()
				.httpBasic().disable()
				.formLogin().disable()
				.exceptionHandling(rejectAsUnauthorized())
				.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS);

		applyRouteRestrictions(http);
		applyOAuth2Config(http);

		http.addFilterBefore(filterChainExceptionHandler(), UsernamePasswordAuthenticationFilter.class);
		http.addFilterBefore(tokenFilter(), UsernamePasswordAuthenticationFilter.class);
	}

	private Customizer<ExceptionHandlingConfigurer<HttpSecurity>> rejectAsUnauthorized() {
		return exceptionHandling -> exceptionHandling.authenticationEntryPoint(
				(request, response, authException) -> response.sendError(403)
		);
	}

	private void applyOAuth2Config(HttpSecurity http) throws Exception {
		http
				.oauth2Login(oauth2Config -> oauth2Config
						.authorizationEndpoint(auth -> {
							auth.baseUri("/auth/oauth2/authorize");
							auth.authorizationRequestRepository(authorizationRequestRepository());
						})
						.redirectionEndpoint(redirect -> redirect.baseUri("/auth/oauth2/code/*"))
						.successHandler(oAuth2SuccessHandler()));
	}

	@Bean
	public JwtFilter tokenFilter() {
		return new JwtFilter();
	}

	@Bean
	public AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository() {
		return new RedirectUriToCookiePersister();
	}

	@Bean
	public FilterChainExceptionHandler filterChainExceptionHandler() {
		return new FilterChainExceptionHandler();
	}

	@Bean
	public SimpleOAuth2SuccessHandler oAuth2SuccessHandler() {
		return new SimpleOAuth2SuccessHandler();
	}
}
