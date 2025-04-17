package com.aniketh.app.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * JPA Entity representing the auth_state table.
 * Stores IP address, a temporary state token, and its creation timestamp.
 * Used for CSRF protection during authentication flows.
 * Uses ipAddress as the primary key.
 */
@Entity
@Table(name = "auth_state")

public class AuthState {

    @Id
    @Column(name = "ip_address", length = 45, nullable = false)
    private String ipAddress;

    @Column(name = "state_token", length = 64, nullable = false) // Matches VARCHAR(64)
    private String stateToken;

    @Column(name = "timestamp", nullable = false) // Matches INT UNSIGNED
    private Long timestamp; // Store as Unix timestamp (seconds since epoch)
    
    public AuthState() {
        // no-args constructor for JPA
    }

    
    public AuthState(String ipAddress, String stateToken, Long timestamp) {
		super();
		this.ipAddress = ipAddress;
		this.stateToken = stateToken;
		this.timestamp = timestamp;
	}

	public String getIpAddress() {
		return ipAddress;
	}

	public void setIpAddress(String ipAddress) {
		this.ipAddress = ipAddress;
	}

	public String getStateToken() {
		return stateToken;
	}

	public void setStateToken(String stateToken) {
		this.stateToken = stateToken;
	}

	public Long getTimestamp() {
		return timestamp;
	}

	public void setTimestamp(Long timestamp) {
		this.timestamp = timestamp;
	}

	/**
     * PrePersist and PreUpdate lifecycle callback to set the timestamp
     * before saving or updating the entity.
     */
    @PrePersist
    @PreUpdate
    protected void onUpdate() {
        // Update timestamp whenever the entity is saved or updated
        // timestamp = Instant.now().getEpochSecond();
        timestamp = System.currentTimeMillis() / 1000;
    }
}