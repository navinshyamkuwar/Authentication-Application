package com.quantum.auth_app_backend.services;

import com.quantum.auth_app_backend.dtos.UserDto;

public interface AuthService {
	UserDto registerUser(UserDto userDto);
}
