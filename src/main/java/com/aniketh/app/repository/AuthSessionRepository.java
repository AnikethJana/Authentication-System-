package com.aniketh.app.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.aniketh.app.entity.AuthSession;

/**
 * Spring Data JPA repository for the AuthSession entity.
 * Provides standard CRUD operations and finder methods.
 */

@Repository
public interface AuthSessionRepository extends JpaRepository<AuthSession, String> { // String is the type of the ID (ipAddress)

    // Optional: Define custom query methods if needed, e.g.,
    // Optional<AuthSession> findByIpAddress(String ipAddress); // Already provided by JpaRepository via findById
	
    // Method to find by IP address (equivalent to findById)
    Optional<AuthSession> findByIpAddress(String ipAddress);

    // Method to delete by IP address (equivalent to deleteById)
    void deleteByIpAddress(String ipAddress);
}
