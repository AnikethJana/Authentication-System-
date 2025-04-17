package com.aniketh.app.entity;

import org.springframework.stereotype.Component;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * JPA Entity representing the auth_sessions table. Stores IP address,
 * associated JWT token, and timestamp. Uses ipAddress as the primary key.
 */
@Entity
@Table(name = "auth_sessions")

public class AuthSession {

	public AuthSession() {

	}

	public AuthSession(String ipAddress, String token, Long timestamp) {

		this.ipAddress = ipAddress;
		this.token = token;
		this.timestamp = timestamp;
	}

	public String getIpAddress() {
		return ipAddress;
	}

	public void setIpAddress(String ipAddress) {
		this.ipAddress = ipAddress;
	}

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}

	public Long getTimestamp() {
		return timestamp;
	}

	public void setTimestamp(Long timestamp) {
		this.timestamp = timestamp;
	}

	@Id // Marks ipAddress as the primary key
	@Column(name = "ip_address", length = 45, nullable = false) // Matches VARCHAR(45)
	private String ipAddress;

	@Lob // Use Lob for potentially long token strings
	@Column(name = "token", nullable = false, columnDefinition = "TEXT")
	private String token;

	@Column(name = "timestamp", nullable = false) // Matches INT UNSIGNED
	private Long timestamp; // Store as Unix timestamp (seconds since epoch)

	/**
	 * PrePersist and PreUpdate lifecycle callback to set the timestamp before
	 * saving or updating the entity.
	 */
	@PrePersist
	@PreUpdate
	protected void onUpdate() {
		// Update timestamp whenever the entity is saved or updated
		// Consider if you only want to update timestamp on creation vs. every update
		// For this logic (matching PHP's ON DUPLICATE KEY UPDATE), updating is correct.
		// timestamp = Instant.now().getEpochSecond();
		// Using System.currentTimeMillis() / 1000 to match PHP's time() more closely
		timestamp = System.currentTimeMillis() / 1000;
	}
}
