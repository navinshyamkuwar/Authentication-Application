package com.quantum.auth_app_backend.controllers;

import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

import org.modelmapper.ModelMapper;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.quantum.auth_app_backend.AuthAppBackendApplication;
import com.quantum.auth_app_backend.dtos.LoginRequest;
import com.quantum.auth_app_backend.dtos.RefreshTokenRequest;
import com.quantum.auth_app_backend.dtos.TokenResponse;
import com.quantum.auth_app_backend.dtos.UserDto;
import com.quantum.auth_app_backend.entities.RefreshToken;
import com.quantum.auth_app_backend.entities.User;
import com.quantum.auth_app_backend.repositories.RefreshTokenRepository;
import com.quantum.auth_app_backend.repositories.UserRepository;
import com.quantum.auth_app_backend.security.CookieService;
import com.quantum.auth_app_backend.security.JwtService;
import com.quantum.auth_app_backend.services.AuthService;

import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;

@RestController
@RequestMapping("/api/v1/auth")
@AllArgsConstructor
public class AuthController {

    private final AuthAppBackendApplication authAppBackendApplication;

	private final AuthService authService;
	private final RefreshTokenRepository refreshTokenRepository;
	
	private final AuthenticationManager authenticationManager;
	private final UserRepository userRepository;
	private final JwtService jwtService;
	private final ModelMapper modelMapper;
	private final CookieService cookieService;

	@PostMapping("/login")
	public ResponseEntity<TokenResponse> loginUser(@RequestBody LoginRequest loginRequest, HttpServletResponse response) {
		Authentication authenticate = authenticate(loginRequest);
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
	
	//access and refresh token renew api
	@PostMapping("/refresh")
	public ResponseEntity<TokenResponse> refreshToken(
			@RequestBody(required = false) RefreshTokenRequest body,
			HttpServletResponse response,
			HttpServletRequest request){
		
		String refreshToken = readRefreshTokenRequest(body, request).orElseThrow(() -> new BadCredentialsException("Refresh token is missing."));
		
		if(!jwtService.isRefreshToken(refreshToken)) {
			throw new BadCredentialsException("Invalid Refresh Token Type");
		}
		
		String jti = jwtService.getJti(refreshToken);
		UUID userId = jwtService.getUserId(refreshToken);
		RefreshToken storedRefreshToken = refreshTokenRepository.findByJti(jti)
				.orElseThrow(() -> new BadCredentialsException("Refresh Token not recognized"));
		
		if(storedRefreshToken.isRevoked()) {
			throw new BadCredentialsException("Refresh Token expired or revoked.");
		}
		
		if(storedRefreshToken.getExpiresAt().isBefore(Instant.now())) {
			throw new BadCredentialsException("Refresh Token is expired.");
		}
		
		if(!storedRefreshToken.getUser().getId().equals(userId)) {
			throw new BadCredentialsException("Refresh Token does not belong to this user");
		}
		
		//refresh token to rotate : important for production
		storedRefreshToken.setRevoked(true);
		String newJti = UUID.randomUUID().toString();
		storedRefreshToken.setReplacedByToken(newJti);
		refreshTokenRepository.save(storedRefreshToken);
		
		User user = storedRefreshToken.getUser();
		var newRefreshTokenOb = RefreshToken.builder()
				.jti(newJti)
				.user(user)
				.createdAt(Instant.now())
				.expiresAt(Instant.now().plusSeconds(jwtService.getRefreshTtlSeconds()))
				.revoked(false)
				.build();
		
		refreshTokenRepository.save(newRefreshTokenOb);
		String newAccessToken = jwtService.generateAccessToken(user);
		String newRefreshToken = jwtService.generateRefreshToken(user, newRefreshTokenOb.getJti());
		
		cookieService.attachRefreshCookie(response, newRefreshToken, (int) jwtService.getRefreshTtlSeconds());
		cookieService.addNoStoreHeaders(response);
		return ResponseEntity.ok(TokenResponse.of(newAccessToken, newRefreshToken, jwtService.getAccessTtlSeconds(), modelMapper.map(user, UserDto.class)));
		
	}
	
	//this method will read refreshToken from request header or body
	private Optional<String> readRefreshTokenRequest(RefreshTokenRequest body, HttpServletRequest request) {
	    // Prefer reading refresh token from cookie
	    
	    if (request.getCookies() != null) {
	        Optional<String> fromCookie = Arrays.stream(request.getCookies())
	                .filter(c -> cookieService.getRefreshTokenCookieName().equals(c.getName()))
	                .map(Cookie::getValue)
	                .filter(v -> !v.isBlank())
	                .findFirst();
	        
	        if(fromCookie.isPresent()) {
	        	return fromCookie;
	        }
	    }
	    
	    // from body
	    if(body!= null && body.refreshToken()!=null && !body.refreshToken().isBlank()) {
	    	return Optional.of(body.refreshToken());
	    }
	    
	    //custom header
	    String refreshHeader = request.getHeader("X-Refresh-Token");
	    if(refreshHeader != null && !refreshHeader.isBlank()) {
	    	return Optional.of(refreshHeader.trim());
	    }
	    
	    //Authorization = Bearer<token>
	    String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
	    if(authHeader != null && authHeader.regionMatches(true, 0, "Bearer",0,7)) {
	    	String candidate = authHeader.substring(7).trim();
	    	if(!candidate.isEmpty()) {
	    		try {
	    			if(jwtService.isRefreshToken(candidate)) {
		    			return Optional.of(candidate);
		    		}
	    		}catch(Exception ignored) {
	    			
	    		}
	    		
	    	}
	    }
	    return Optional.empty();
	}
	
	@PostMapping("/logout")
	public ResponseEntity<String> logout(HttpServletRequest request, HttpServletResponse response){
		
		readRefreshTokenRequest(null, request).ifPresent(token -> {
			try {
				if(jwtService.isRefreshToken(token)) {
					String jti = jwtService.getJti(token);
					refreshTokenRepository.findByJti(jti).ifPresent(rt -> {
						rt.setRevoked(true);
						refreshTokenRepository.save(rt);
					});
				}
			}catch(JwtException ignored) {
				
			}
		});
		
		cookieService.clearRefreshCookie(response);
		cookieService.addNoStoreHeaders(response);
		SecurityContextHolder.clearContext();
		return ResponseEntity.ok("You have successfully logged out.");
		}

	@PostMapping("/register")
	public ResponseEntity<UserDto> registerUser(@RequestBody UserDto userDto) {
		return ResponseEntity.status(HttpStatus.CREATED).body(authService.registerUser(userDto));
	}
}
