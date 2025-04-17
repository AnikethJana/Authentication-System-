package com.aniketh.app.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.NonNull; // Use NonNull for required fields in constructor
import lombok.RequiredArgsConstructor;


/**
 * DTO for sending authentication status responses.
 */
@Data
@NoArgsConstructor // Needed for Jackson deserialization if used
@RequiredArgsConstructor // Creates constructor for final/NonNull fields
@JsonInclude(JsonInclude.Include.NON_NULL) // Don't include null fields in JSON output
public class AuthResponse {

    @NonNull // Mark authenticated as required
    private Boolean authenticated;

    private String method; // e.g., "token", "ip_refresh", "token_ip_updated", "token_verified"
    private String reason; // Reason for failure (e.g., "Invalid token", "IP mismatch")
    private String error;  // Generic error message for server errors

    public Boolean getAuthenticated() {
		return authenticated;
	}

	public void setAuthenticated(Boolean authenticated) {
		this.authenticated = authenticated;
	}

	public String getMethod() {
		return method;
	}

	public void setMethod(String method) {
		this.method = method;
	}

	public String getReason() {
		return reason;
	}

	public void setReason(String reason) {
		this.reason = reason;
	}

	public String getError() {
		return error;
	}

	public void setError(String error) {
		this.error = error;
	}

	// Convenience constructor for success cases
    public AuthResponse(boolean authenticated) {
        this.authenticated = authenticated;
    }

     // Convenience constructor for failure cases with reason
    public AuthResponse(boolean authenticated, String reason) {
        this.authenticated = authenticated;
        this.reason = reason;
    }

     // Convenience constructor for success cases with method
     public AuthResponse(boolean authenticated, String method, String reasonOrError) {
        this.authenticated = authenticated;
        this.method = method;
        // Decide if it's a reason or an error based on context where it's called
        if (!authenticated && reasonOrError != null) {
             this.reason = reasonOrError;
        } else if (reasonOrError != null) {
            // Could potentially set error here too if needed
            this.error = reasonOrError; // Or keep separate setters/constructors
        }
     }
}
