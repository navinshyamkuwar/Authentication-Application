package com.quantum.auth_app_backend.services.impl;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.quantum.auth_app_backend.dtos.UserDto;
import com.quantum.auth_app_backend.services.AuthService;
import com.quantum.auth_app_backend.services.UserService;

import lombok.AllArgsConstructor;

@Service
@AllArgsConstructor
public class AuthServiceImpl implements AuthService {
	
	private final UserService userService;
	private final PasswordEncoder passwordEncoder;

	@Override
	public UserDto registerUser(UserDto userDto) {
		// TODO Verify email and password before creating user
		userDto.setPassword(passwordEncoder.encode(userDto.getPassword()));
		return  userService.createUser(userDto);
	}

}
