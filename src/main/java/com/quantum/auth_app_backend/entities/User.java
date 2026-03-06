package com.quantum.auth_app_backend.entities;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
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
@Entity
@Table(name = "users")
public class User {
	@Id
	@GeneratedValue(strategy = GenerationType.UUID)
	@Column(name = "user_id")
	private UUID id;
	@Column(name = "user_name", unique = true, length = 50)
	private String username;
	@Column(name = "user_email", unique = true, length = 100)
	private String email;
	private String password;
	private String imageUrl;
	private boolean enabled = true;
	private Instant createdAt = Instant.now();
	private Instant updatedAt = Instant.now();
	
//	private String gender;
//	private Address address;
	
	@Enumerated(EnumType.STRING)
	private Provider provider = Provider.LOCAL;
	
	@ManyToMany(fetch = FetchType.EAGER)
	@JoinTable(name = "user_roles",
		joinColumns = @JoinColumn(name = "user_id"),
		inverseJoinColumns = @JoinColumn(name = "role_id"))
	private Set<Role> roles = new HashSet<>();
	
	@PrePersist
	protected void onCreate() {
		Instant now = Instant.now();
		if (createdAt == null) {
			createdAt = now;
		}
		updatedAt = now;
	}
	
	@PreUpdate
	protected void onUpdate() {
		updatedAt = Instant.now();
	}
}
