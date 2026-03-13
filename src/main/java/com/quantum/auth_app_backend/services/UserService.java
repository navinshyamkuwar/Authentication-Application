package com.quantum.auth_app_backend.services;

import com.quantum.auth_app_backend.dtos.UserDto;

public interface UserService {
	UserDto createUser(UserDto userDto);
	UserDto getUserByEmail(String email);
	UserDto getUserById(String userId);
	UserDto updateUser(UserDto userDto, String userId);
	void deleteUser(String userId);
	Iterable<UserDto> getAllUsers();
}
