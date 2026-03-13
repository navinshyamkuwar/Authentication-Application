package com.quantum.auth_app_backend.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.quantum.auth_app_backend.dtos.ErrorResponse;

@RestControllerAdvice
public class GlobalExceptionHandler {
	
	@ExceptionHandler(ResourceNotFoundException.class)
	public ResponseEntity<ErrorResponse> handleResourceNotFoundException(ResourceNotFoundException ex) {
		ErrorResponse internalServerError = new ErrorResponse(ex.getMessage(), HttpStatus.NOT_FOUND, 404);
		return ResponseEntity.status(HttpStatus.NOT_FOUND).body(internalServerError);
	}
	
	@ExceptionHandler(IllegalArgumentException.class)
	public ResponseEntity<ErrorResponse> handleIllegalArgumentException(IllegalArgumentException ex) {
		ErrorResponse internalServerError = new ErrorResponse(ex.getMessage(), HttpStatus.BAD_REQUEST, 400);
		return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(internalServerError);
	}

}
