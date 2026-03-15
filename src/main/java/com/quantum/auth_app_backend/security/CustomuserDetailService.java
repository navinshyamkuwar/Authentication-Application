package com.quantum.auth_app_backend.security;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.quantum.auth_app_backend.exceptions.ResourceNotFoundException;
import com.quantum.auth_app_backend.repositories.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class CustomuserDetailService implements UserDetailsService {
	
	private final UserRepository userRepository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

		return userRepository.findByEmail(username).
						orElseThrow(() -> new ResourceNotFoundException("Invalid email or password: "));
	}

}
