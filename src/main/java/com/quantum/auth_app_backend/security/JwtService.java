package com.quantum.auth_app_backend.security;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.quantum.auth_app_backend.entities.Role;
import com.quantum.auth_app_backend.entities.User;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import lombok.Setter;

@Service
@Getter
@Setter
public class JwtService {
	
	private final SecretKey key;
	private final long accessTtlSeconds;
	private final long refreshTtlSeconds;
	private final String issuer;
	
	public JwtService(
			@Value("${security.jwt.secret}") String secret,
			@Value("${security.jwt.access-ttl-seconds}") long accessTtlSeconds,
			@Value("${security.jwt.refresh-ttl-seconds}") long refreshTtlSeconds,
			@Value("${security.jwt.issuer}")String issuer) {
		
		if(secret == null || secret.length() < 64) {
			throw new IllegalArgumentException("Invalid JWT secret key. It must be at least 64 characters long.");
		}
		
		this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
		this.accessTtlSeconds = accessTtlSeconds;
		this.refreshTtlSeconds = refreshTtlSeconds;
		this.issuer = issuer;
	}
	
	//generate access token with user id as subject and email, roles as claims
	public String generateAccessToken(User user) {
		Instant now = Instant.now();
		List<String> roles = user.getRoles() == null ? List.of():
				user.getRoles().stream().map(Role::getName).toList();
		
		return Jwts.builder()
				.id(UUID.randomUUID().toString())
				.subject(user.getId().toString())
				.issuer(issuer)
				.issuedAt(Date.from(now))
				.expiration(Date.from(now.plusSeconds(accessTtlSeconds)))
				.claims(Map.of(
						"email", user.getEmail(),
						"roles", roles,
						"typ", "access"))
				.signWith(key, SignatureAlgorithm.HS512)
				.compact();
	}
	
	//generate refresh token with type claim as "refresh" and jti as unique identifier for token revocation
	public String generateRefreshToken(User user, String jti) {
		Instant now = Instant.now();
		
		return Jwts.builder()
				.id(jti)
				.subject(user.getId().toString())
				.issuer(issuer)
				.issuedAt(Date.from(now))
				.expiration(Date.from(now.plusSeconds(refreshTtlSeconds)))
				.claim("typ", "refresh")
				.signWith(key, SignatureAlgorithm.HS512)
				.compact();
	}
	
	//parse and validate the token, return claims if valid, throw exception if invalid	
	public Jws<Claims> parse(String token) {
		return Jwts.parser()
				.verifyWith(key).build()
				.parseSignedClaims(token);
	}
	
	//check if the token is access token based on the "typ" claim
	public boolean isAccessToken(String token) {
		Claims c = parse(token).getPayload();
		return "access".equals(c.get("typ"));
	}
	
	//check if the token is refresh token based on the "typ" claim
	public boolean isRefreshToken(String token) {
		Claims c = parse(token).getPayload();
		return "refresh".equals(c.get("typ"));
	}
	
	//get user id from token subject
	public UUID getUserId(String token) {
		Claims c = parse(token).getPayload();
		return UUID.fromString(c.getSubject());
	}
	
	//get jti from token for refresh token revocation
	public String getJti(String token) {
		Claims c = parse(token).getPayload();
		return c.getId();
	}
}

