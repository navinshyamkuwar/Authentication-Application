package com.quantum.auth_app_backend.config;

import java.util.Map;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.NullSecurityContextRepository;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.quantum.auth_app_backend.security.JwtAuthenticationFilter;

@Configuration
public class SecurityConfig {
	
	private JwtAuthenticationFilter jwtAuthenticationFilter;
	private AuthenticationSuccessHandler successHandler;
	
	public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter, AuthenticationSuccessHandler successHandler) {
		this.jwtAuthenticationFilter = jwtAuthenticationFilter;
		this.successHandler = successHandler;
	}

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		
		http.csrf(csrf -> csrf.disable())
			.cors(Customizer.withDefaults())
			.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))			
			.securityContext(securityContext -> securityContext.requireExplicitSave(false))
			.securityContext(context -> context
			        .securityContextRepository(new NullSecurityContextRepository()))
			.authorizeHttpRequests(authorizeHttpRequests -> authorizeHttpRequests
				.requestMatchers("/api/v1/auth/**").permitAll()
				.anyRequest().authenticated())
			.oauth2Login(oauth2 -> 
					oauth2.successHandler(successHandler)
							.failureHandler(null)
			)
			.logout(logout -> logout.disable())
			
			.exceptionHandling(ex -> ex.authenticationEntryPoint((request, response, authException) -> {
				authException.printStackTrace();
				response.setStatus(401);
				response.setContentType("application/json");
				String message = "Unauthorized access! " + authException.getMessage();
				Map<String, String> errorMap = Map.of("message", message, "statusCode", Integer.toString(401));
				var objectMapper = new ObjectMapper();
				response.getWriter().write(objectMapper.writeValueAsString(errorMap));
			}))
			.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);		
		return http.build();
	}

    @Bean
    PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();		
	}

    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
		return configuration.getAuthenticationManager();
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
