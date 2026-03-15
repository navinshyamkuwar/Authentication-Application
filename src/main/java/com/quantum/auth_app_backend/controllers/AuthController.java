package com.quantum.auth_app_backend.controllers;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.quantum.auth_app_backend.dtos.UserDto;
import com.quantum.auth_app_backend.services.AuthService;

import lombok.AllArgsConstructor;

@RestController
@RequestMapping("/api/v1/auth")
@AllArgsConstructor
public class AuthController {
	
	private final AuthService authService;
	
	@PostMapping("/register")
	public ResponseEntity<UserDto> registerUser(@RequestBody UserDto userDto) {
		return ResponseEntity.status(HttpStatus.CREATED).body(authService.registerUser(userDto));
	}
}
