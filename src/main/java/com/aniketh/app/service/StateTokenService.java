package com.aniketh.app.service;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.aniketh.app.entity.AuthState;
import com.aniketh.app.repository.AuthStateRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Service for managing state tokens used in authentication flows (e.g., OAuth, CSRF protection).
 * Handles generation, storage, verification, and cleanup of state tokens.
 */
@Service
public class StateTokenService {

    private static final Logger log = LoggerFactory.getLogger(StateTokenService.class);
    private static final SecureRandom secureRandom = new SecureRandom(); // Thread-safe generator
    private static final int STATE_TOKEN_BYTES = 16; // Number of random bytes for the token part

    @Autowired
    private AuthStateRepository authStateRepository;

    @Autowired
    private ObjectMapper objectMapper; // For JSON processing

    @Value("${state.token.expiration.seconds}")
    private long stateExpirationSeconds; // Expiration time from application.properties

    /**
     * Generates a cryptographically secure random state token (hex string).
     *
     * @return A 32-character hexadecimal state token.
     */
    private String generateRandomTokenPart() {
        byte[] bytes = new byte[STATE_TOKEN_BYTES];
        secureRandom.nextBytes(bytes);
        // Convert bytes to hex string
        StringBuilder hexString = new StringBuilder(2 * bytes.length);
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    /**
     * Generates a state token, potentially encoding additional parameters within it.
     * Format: 'random_token_part:url_encoded_json_params' or just 'random_token_part' if no params.
     *
     * @param params Optional parameters to encode into the state token.
     * @return The generated state token string.
     */
    public String createStateToken(Map<String, String> params) {
        String randomPart = generateRandomTokenPart();
        if (params == null || params.isEmpty()) {
            return randomPart;
        }

        try {
            String jsonParams = objectMapper.writeValueAsString(params);
            String encodedParams = URLEncoder.encode(jsonParams, StandardCharsets.UTF_8);
            return randomPart + ":" + encodedParams;
        } catch (JsonProcessingException e) {
            log.error("Error encoding parameters into JSON for state token: {}", e.getMessage(), e);
            // Fallback to just the random part if encoding fails
            return randomPart;
        }
    }


    /**
     * Stores the state token associated with an IP address in the database.
     * Replaces any existing state token for the same IP.
     *
     * @param ipAddress  The client's IP address.
     * @param stateToken The state token to store (can include encoded params).
     * @return true if storage was successful, false otherwise.
     */
    @Transactional // Ensure atomicity
    public boolean storeStateToken(String ipAddress, String stateToken) {
        try {
            // Extract only the random part for storage if needed, or store the full token.
            // Storing the full token might be simpler if extraction logic is robust.
            // Let's store the full token for now.
            AuthState authState = new AuthState(ipAddress, stateToken, System.currentTimeMillis() / 1000);
            authStateRepository.save(authState); // save() handles insert or update based on ID existence
            log.debug("Stored state token for IP: {}", ipAddress);
            return true;
        } catch (Exception e) {
            log.error("Failed to store state token for IP {}: {}", ipAddress, e.getMessage(), e);
            return false;
        }
    }

    /**
     * Verifies the provided state token against the one stored for the IP address.
     * Deletes the token after successful verification (one-time use). Checks expiration.
     *
     * @param ipAddress          The client's IP address.
     * @param receivedStateToken The full state token received from the client (may include encoded params).
     * @return true if the token is valid, matches the stored one, and is not expired; false otherwise.
     */
    @Transactional // Ensure find and delete happen atomically regarding this token
    public boolean verifyAndConsumeStateToken(String ipAddress, String receivedStateToken) {
        if (receivedStateToken == null || receivedStateToken.isEmpty()) {
             log.warn("Verification failed: Received state token is null or empty for IP {}", ipAddress);
            return false;
        }

        Optional<AuthState> storedStateOpt = authStateRepository.findByIpAddress(ipAddress);

        if (storedStateOpt.isEmpty()) {
            log.warn("Verification failed: No state token found in DB for IP: {}", ipAddress);
            return false;
        }

        AuthState storedState = storedStateOpt.get();
        String storedFullToken = storedState.getStateToken(); // The token stored in DB (potentially with params)
        long storedTimestamp = storedState.getTimestamp();

        boolean isValid = false;
        try {
            // Compare the full received token with the full stored token
            // Use a constant-time comparison if possible, though less critical for state tokens than passwords
            if (storedFullToken.equals(receivedStateToken)) {
                // Check expiration (e.g., 10 minutes)
                long nowSeconds = System.currentTimeMillis() / 1000;
                if ((nowSeconds - storedTimestamp) <= stateExpirationSeconds) {
                    isValid = true;
                    log.debug("State token verified successfully for IP: {}", ipAddress);
                } else {
                    log.warn("Verification failed: State token expired for IP: {}. Stored: {}, Now: {}", ipAddress, storedTimestamp, nowSeconds);
                }
            } else {
                log.warn("Verification failed: State token mismatch for IP: {}. Received: '{}', Expected: '{}'", ipAddress, receivedStateToken, storedFullToken);
            }
        } finally {
             // --- Crucial: Consume (delete) the token regardless of validity ---
             // This prevents replay attacks with the same token, even if it failed verification once.
             try {
                 authStateRepository.deleteByIpAddress(ipAddress);
                 log.debug("Consumed (deleted) state token for IP: {}", ipAddress);
             } catch (Exception deleteEx) {
                 // Log error during deletion but don't change the 'isValid' result based on this.
                 // The primary goal was verification. Deletion failure is a secondary issue.
                 log.error("Error deleting state token after verification attempt for IP {}: {}", ipAddress, deleteEx.getMessage(), deleteEx);
             }
        }

        return isValid;
    }


    /**
     * Extracts original parameters encoded in the state token.
     * Format: 'token:url_encoded_json_string'.
     *
     * @param stateToken The state token potentially containing encoded parameters.
     * @return A Map of the original parameters, or an empty map if none found or error.
     */
    public Map<String, String> extractOriginalParams(String stateToken) {
        if (stateToken == null || !stateToken.contains(":")) {
            return Collections.emptyMap(); // No parameters encoded
        }

        String[] parts = stateToken.split(":", 2);
        if (parts.length < 2 || parts[1].isEmpty()) {
            return Collections.emptyMap(); // No parameter part found
        }

        try {
            String encodedParams = parts[1];
            String jsonParams = URLDecoder.decode(encodedParams, StandardCharsets.UTF_8);
            // Define the type reference for deserializing into Map<String, String>
            TypeReference<Map<String, String>> typeRef = new TypeReference<>() {};
            return objectMapper.readValue(jsonParams, typeRef);
        } catch (Exception e) { // Catch potential JsonProcessingException, UnsupportedEncodingException
            log.error("Error decoding or parsing parameters from state token: {}", e.getMessage(), e);
            return Collections.emptyMap(); // Return empty map on error
        }
    }
}