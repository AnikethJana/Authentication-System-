package com.aniketh.app.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO for receiving a token in a request body (e.g., for /verify-token).
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class TokenRequest {
    private String token;

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}
}
