package com.quantum.auth_app_backend.services.impl;

import java.time.Instant;
import java.util.UUID;

import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;

import com.quantum.auth_app_backend.dtos.UserDto;
import com.quantum.auth_app_backend.entities.Provider;
import com.quantum.auth_app_backend.entities.User;
import com.quantum.auth_app_backend.exceptions.ResourceNotFoundException;
import com.quantum.auth_app_backend.helpers.UserHelper;
import com.quantum.auth_app_backend.repositories.UserRepository;
import com.quantum.auth_app_backend.services.UserService;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
	
	private final UserRepository userRepository;
	private final ModelMapper modelMapper;

	@Override
	@Transactional
	public UserDto createUser(UserDto userDto) {
		
		if(userDto.getEmail() == null || userDto.getEmail().isBlank()) {
			throw new IllegalArgumentException("Email is required");
		}
		
		if(userRepository.existsByEmail(userDto.getEmail())) {
			throw new IllegalArgumentException("User with given email already exists");
		}
		
		User user = modelMapper.map(userDto,User.class);
		user.setProvider(userDto.getProvider()!=null ? userDto.getProvider() : Provider.LOCAL);
		//TODO: Assign role to user based on provider
		
		User savedUser = userRepository.save(user);		
		return modelMapper.map(savedUser, UserDto.class);				
	}

	@Override
	public UserDto getUserByEmail(String email) {
		
		User user = userRepository.findByEmail(email)
			.orElseThrow(() -> new ResourceNotFoundException("User not found with given email: " + email));
		
		return modelMapper.map(user, UserDto.class);
	}

	@Override
	public UserDto updateUser(UserDto userDto, String userId) {
		
		UUID uid = UserHelper.parseUUID(userId);
		User existingUser = userRepository.findById(uid)
			.orElseThrow(() -> new ResourceNotFoundException("User not found with given id: " + userId));
		if(userDto.getUsername()!=null) existingUser.setUsername(userDto.getUsername());
		if(userDto.getImageUrl()!=null) existingUser.setImageUrl(userDto.getImageUrl());
		if(userDto.getProvider()!=null) existingUser.setProvider(userDto.getProvider());
		//TODO change the password updation logic
		if(userDto.getPassword()!=null) existingUser.setPassword(userDto.getPassword());
		existingUser.setEnabled(userDto.isEnabled());
		existingUser.setUpdatedAt(Instant.now());
		User updatedUser = userRepository.save(existingUser);
		return modelMapper.map(updatedUser, UserDto.class);
	}

	@Override
	public void deleteUser(String userId) {
		
		UUID uid = UserHelper.parseUUID(userId);
		User user = userRepository.findById(uid)
			.orElseThrow(() -> new ResourceNotFoundException("User not found with given id: " + userId));
		userRepository.delete(user);
	}

	@Override
	public Iterable<UserDto> getAllUsers() {	
		// TODO Auto-generated method stub
		return userRepository.findAll().stream()
				.map(user -> modelMapper.map(user, UserDto.class))
				.toList();
	}

	@Override
	public UserDto getUserById(String userId) {

		User user = userRepository.findById(UserHelper.parseUUID(userId))
			.orElseThrow(() -> new ResourceNotFoundException("User not found with given id: " + userId));
		
		return modelMapper.map(user, UserDto.class);
	}

}
