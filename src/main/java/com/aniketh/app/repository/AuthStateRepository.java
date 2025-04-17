package com.aniketh.app.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.aniketh.app.entity.AuthState;

/**
 * Spring Data JPA repository for the AuthState entity.
 * Provides standard CRUD operations and finder methods.
 */
@Repository
public interface AuthStateRepository extends JpaRepository<AuthState, String> { // String is the type of the ID (ipAddress)

    // Method to find by IP address (equivalent to findById)
    Optional<AuthState> findByIpAddress(String ipAddress);

    // Method to delete by IP address (needed for state token cleanup)
    // Ensure this runs within a transaction
    @Transactional
    void deleteByIpAddress(String ipAddress);
}
