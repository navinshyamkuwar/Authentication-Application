package com.quantum.auth_app_backend.repositories;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import com.quantum.auth_app_backend.entities.User;

public interface UserRepository extends JpaRepository<User, UUID> {
	
//	Optional<User> findByUsername(String username);
	Optional<User> findByEmail(String email);
	boolean existsByEmail(String email);
	
}
