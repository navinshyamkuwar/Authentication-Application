package com.quantum.auth_app_backend.repositories;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import com.quantum.auth_app_backend.entities.RefreshToken;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID>{
	
	Optional<RefreshToken> findByJti(String jti);
}
