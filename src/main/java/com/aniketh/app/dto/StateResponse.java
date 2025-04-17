package com.aniketh.app.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO for sending the generated state token back to the client.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class StateResponse {
    private boolean success;
    private String state; // The generated state token
    private String error; // Optional error message
	public boolean isSuccess() {
		return success;
	}
	public void setSuccess(boolean success) {
		this.success = success;
	}
	public String getState() {
		return state;
	}
	public void setState(String state) {
		this.state = state;
	}
	public String getError() {
		return error;
	}
	public void setError(String error) {
		this.error = error;
	}
	public StateResponse(boolean success, String state, String error) {
		super();
		this.success = success;
		this.state = state;
		this.error = error;
	}
    
}
