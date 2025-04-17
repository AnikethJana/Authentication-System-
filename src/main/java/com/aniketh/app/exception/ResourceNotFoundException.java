package com.aniketh.app.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
* Custom exception for cases where a requested resource is not found.
* Results in an HTTP 404 Not Found status.
*/
@ResponseStatus(HttpStatus.NOT_FOUND)
public class ResourceNotFoundException extends RuntimeException {
 public ResourceNotFoundException(String message) {
     super(message);
 }

 public ResourceNotFoundException(String message, Throwable cause) {
     super(message, cause);
 }
}