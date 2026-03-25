package com.quantum.auth_app_backend.exceptions;

import javax.security.auth.login.CredentialExpiredException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.quantum.auth_app_backend.dtos.ApiError;
import com.quantum.auth_app_backend.dtos.ErrorResponse;

import jakarta.servlet.http.HttpServletRequest;

@RestControllerAdvice
public class GlobalExceptionHandler {
	
	private final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);
	
	@ExceptionHandler({
						UsernameNotFoundException.class,
						BadCredentialsException.class, 
						CredentialExpiredException.class,
						DisabledException.class
					 })
	public ResponseEntity<ApiError> handleAuthException(Exception ex, HttpServletRequest request) {
		logger.info("Exception occurred: {}", ex.getClass().getName());
		var apiError = ApiError.of(HttpStatus.BAD_REQUEST.value(),"Bad Request", ex.getMessage(), request.getRequestURI());
		return ResponseEntity.badRequest().body(apiError);
	}
	
	
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
