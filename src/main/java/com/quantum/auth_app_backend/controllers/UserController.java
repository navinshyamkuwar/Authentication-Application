package com.quantum.auth_app_backend.controllers;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.quantum.auth_app_backend.dtos.UserDto;
import com.quantum.auth_app_backend.services.UserService;

import lombok.AllArgsConstructor;

@RestController
@RequestMapping("/api/v1/users")
@AllArgsConstructor
public class UserController {
	
	private final UserService userService;
	
	@PostMapping("/create")
	public ResponseEntity<UserDto> createUser(@RequestBody UserDto userDto) {
		return ResponseEntity.status(HttpStatus.CREATED).body(userService.createUser(userDto));
		
	}
	
	//get all users
	@GetMapping()
	public ResponseEntity<Iterable<UserDto>> getAllUsers() {
		return ResponseEntity.ok(userService.getAllUsers());
	}
	
	@GetMapping("/email/{email}")
	public ResponseEntity<UserDto> getUserByEmail(@PathVariable String email) {
		return ResponseEntity.ok(userService.getUserByEmail(email));
	}
	
	@DeleteMapping("/{userId}")
	public String deleteUser(@PathVariable String userId) {
		userService.deleteUser(userId);
		return "User deleted successfully";
	}
	
	@PutMapping("/{userId}")
	public ResponseEntity<UserDto> updateUser(@RequestBody UserDto userDto, @PathVariable String userId) {
		return ResponseEntity.ok(userService.updateUser(userDto, userId));
	}
	
	@GetMapping("/{userId}")
	public ResponseEntity<UserDto> getUserById(@PathVariable String userId) {
		return ResponseEntity.ok(userService.getUserById(userId));
	}

}
