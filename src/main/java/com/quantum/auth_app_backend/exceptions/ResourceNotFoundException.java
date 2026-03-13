package com.quantum.auth_app_backend.exceptions;

public class ResourceNotFoundException extends RuntimeException {
	public ResourceNotFoundException(String message) {
		super(message);
	}
	
	public ResourceNotFoundException() {
		super("Resource not found !!");
	}

}
