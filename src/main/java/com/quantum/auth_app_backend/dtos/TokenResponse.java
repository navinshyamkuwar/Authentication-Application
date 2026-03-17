package com.quantum.auth_app_backend.dtos;

public record TokenResponse(
		String accessToken,
		String refreshToken,
		long expiresIn,
		String tokenType,
		UserDto userDto
) {
	
	public static TokenResponse of(String accessToken, String refreshToken, long expiresIn, UserDto userDto) {
		return new TokenResponse(accessToken, refreshToken, expiresIn, "Bearer", userDto);
	}
	
}
