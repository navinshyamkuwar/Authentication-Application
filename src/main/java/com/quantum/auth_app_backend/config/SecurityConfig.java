package com.quantum.auth_app_backend.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {
	
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		
		http.csrf(csrf -> csrf.disable());
		http.authorizeHttpRequests(authorizeHttpRequests -> authorizeHttpRequests
				.requestMatchers("/api/v1/auth/register").permitAll()
				.requestMatchers("/api/v1/auth/login").permitAll()
				.anyRequest().authenticated())
		.httpBasic(Customizer.withDefaults());
		
		return http.build();
	}
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();		
	}
	
//	@Bean
//	public UserDetailsService users() {
//		User.UserBuilder userBuilder = User.withDefaultPasswordEncoder();
//		
//		UserDetails user1 = userBuilder.username("manav").password("manav123").roles("ADMIN").build();
//		UserDetails user2 = userBuilder.username("raghu").password("raghu123").roles("GUEST").build();
//		UserDetails user3 = userBuilder.username("swaym").password("swaym123").roles("USER").build();
//		
//		return new InMemoryUserDetailsManager(user1, user2, user3);
//	}
}
