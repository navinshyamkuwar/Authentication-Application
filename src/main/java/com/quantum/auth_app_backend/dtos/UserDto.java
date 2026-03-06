package com.quantum.auth_app_backend.dtos;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import com.quantum.auth_app_backend.entities.Provider;
import com.quantum.auth_app_backend.entities.Role;

import jakarta.persistence.Column;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserDto {
	private UUID id;
	private String username;
	private String email;
	private String password;
	private String imageUrl;
	private boolean enabled = true;
	private Instant createdAt = Instant.now();
	private Instant updatedAt = Instant.now();
	private Provider provider = Provider.LOCAL;	
	private Set<Role> roles = new HashSet<>();
}
