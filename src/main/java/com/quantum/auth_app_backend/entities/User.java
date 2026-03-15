package com.quantum.auth_app_backend.entities;

import java.time.Instant;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

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
public class User implements UserDetails {
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

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return roles.stream()
			.map(role -> new SimpleGrantedAuthority(role.getName()))
			.toList();
	}
	
	@Override
	public String getUsername() {
		return this.email; // Use email as the username for authentication
	}
	
	@Override
	public boolean isAccountNonExpired() {
		return true; // Implement logic if you want to support account expiration
	}
	
	@Override
	public boolean isAccountNonLocked() {
		return true; // Implement logic if you want to support account locking
	}
	
	@Override
	public boolean isCredentialsNonExpired() {
		return true; // Implement logic if you want to support credential expiration
	}
	
	@Override
	public boolean isEnabled() {
		return this.enabled; // Use the enabled field to determine if the account is active
	}
}
