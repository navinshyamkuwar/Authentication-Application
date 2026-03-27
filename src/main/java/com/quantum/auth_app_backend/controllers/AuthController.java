package com.quantum.auth_app_backend.controllers;

import java.time.Instant;
import java.util.UUID;

import org.modelmapper.ModelMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.quantum.auth_app_backend.dtos.LoginRequest;
import com.quantum.auth_app_backend.dtos.TokenResponse;
import com.quantum.auth_app_backend.dtos.UserDto;
import com.quantum.auth_app_backend.entities.RefreshToken;
import com.quantum.auth_app_backend.entities.User;
import com.quantum.auth_app_backend.repositories.RefreshTokenRepository;
import com.quantum.auth_app_backend.repositories.UserRepository;
import com.quantum.auth_app_backend.security.CookieService;
import com.quantum.auth_app_backend.security.JwtService;
import com.quantum.auth_app_backend.services.AuthService;

import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;

@RestController
@RequestMapping("/api/v1/auth")
@AllArgsConstructor
public class AuthController {

	private final AuthService authService;
	private final RefreshTokenRepository refreshTokenRepository;
	
	private final AuthenticationManager authenticationManager;
	private final UserRepository userRepository;
	private final JwtService jwtService;
	private final ModelMapper modelMapper;
	private final CookieService cookieService;


	@PostMapping("/login")
	public ResponseEntity<TokenResponse> loginUser(@RequestBody LoginRequest loginRequest, HttpServletResponse response) {
		Authentication authentication = authenticate(loginRequest);
		User user = userRepository.findByEmail(loginRequest.email())
				.orElseThrow(() -> new BadCredentialsException("Invalid email or password"));
		if(!user.isEnabled()) {
			throw new DisabledException("User account is disabled");
		}
		
		String jti = UUID.randomUUID().toString();
		var refreshTokenOb = RefreshToken.builder()
				.jti(jti)
				.user(user)
				.createdAt(Instant.now())
				.expiresAt(Instant.now().plusSeconds(jwtService.getRefreshTtlSeconds()))
				.revoked(false)
				.build();
		//Refresh token information will be saved in database
		refreshTokenRepository.save(refreshTokenOb);
				
		
		String accessToken = jwtService.generateAccessToken(user);
		String refreshToken = jwtService.generateRefreshToken(user, refreshTokenOb.getJti());
		
		//use cookie service to attach refresh token in cookie
		cookieService.attachRefreshCookie(response, refreshToken, (int)jwtService.getRefreshTtlSeconds());
		cookieService.addNoStoreHeaders(response);
		
		
		TokenResponse tokenResponse = TokenResponse.of(accessToken,refreshToken,jwtService.getAccessTtlSeconds(), modelMapper.map(user, UserDto.class));
		return ResponseEntity.ok(tokenResponse);
	}

	private Authentication authenticate(LoginRequest loginRequest) {
		try {
			return authenticationManager.authenticate(
					new UsernamePasswordAuthenticationToken(
							loginRequest.email(),
							loginRequest.password()
					)
			);
		} catch (Exception e) {
			throw new BadCredentialsException("Invalid Username or Password");
		}
	}

	@PostMapping("/register")
	public ResponseEntity<UserDto> registerUser(@RequestBody UserDto userDto) {
		return ResponseEntity.status(HttpStatus.CREATED).body(authService.registerUser(userDto));
	}
}
