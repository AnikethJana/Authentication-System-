package com.aniketh.app.service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.annotation.PostConstruct;

/**
 * Service for handling JWT (JSON Web Token) operations:
 * - Generation of tokens
 * - Validation of tokens (signature, expiration)
 * - Extraction of claims from tokens
 */
@Service
public class JwtService {

    private static final Logger log = LoggerFactory.getLogger(JwtService.class);

    @Value("${jwt.secret}")
    private String secret; // JWT secret key from application.properties

    @Value("${jwt.expiration.ms}")
    private long expirationMs; // Token expiration time in milliseconds from application.properties

    private SecretKey key; // The SecretKey object derived from the secret string

    /**
     * Initializes the SecretKey after the bean is constructed.
     * Converts the secret string (expected to be hex) into a byte array
     * and creates a SecretKey suitable for HMAC-SHA algorithms.
     */
    @PostConstruct
    protected void init() {
        // Assuming the secret is a hex-encoded string like in the PHP example
        try {
            byte[] keyBytes = hexStringToByteArray(secret);
            // Ensure the key length is sufficient for HS256 (at least 256 bits / 32 bytes)
            if (keyBytes.length < 32) {
                 log.error("JWT secret key length is less than 32 bytes (256 bits), which is required for HS256. Actual length: {} bytes.", keyBytes.length);
                 // You might throw an exception here or use a default secure key for development ONLY
                 // throw new IllegalArgumentException("JWT secret key must be at least 32 bytes (256 bits) long for HS256.");
                 // For now, let's log the error and proceed, but this is insecure.
            }
            this.key = Keys.hmacShaKeyFor(keyBytes);
            log.info("JWT SecretKey initialized successfully.");
        } catch (Exception e) {
             log.error("Failed to initialize JWT SecretKey from hex string. Ensure jwt.secret is a valid hex string.", e);
             // Handle initialization failure, maybe throw an exception to prevent startup?
             throw new RuntimeException("Failed to initialize JWT key", e);
        }
    }

    /**
     * Generates a JWT token for the given IP address.
     *
     * @param ipAddress The IP address to include in the token claims.
     * @return The generated JWT string.
     */
    public String generateToken(String ipAddress) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("ip", ipAddress); // Add IP address claim
        // Add other claims if needed, e.g., username, roles

        return createToken(claims);
    }

    /**
     * Creates the JWT string with the given claims.
     * Sets issued at, expiration date, and signs the token.
     *
     * @param claims The claims to include in the token payload.
     * @return The JWT string.
     */
    private String createToken(Map<String, Object> claims) {
        Date now = new Date();
        Date expirationDate = new Date(now.getTime() + expirationMs);

        return Jwts.builder()
                .setClaims(claims) // Set custom claims
                .setIssuedAt(now) // Set issued at time
                .setExpiration(expirationDate) // Set expiration time
                .signWith(key, SignatureAlgorithm.HS256) // Sign with HS256 algorithm and the key
                .compact(); // Build the token string
    }

    /**
     * Validates a JWT token. Checks signature and expiration.
     *
     * @param token The JWT token string.
     * @return Optional containing the decoded Claims if valid, empty otherwise.
     */
    public Optional<Claims> validateTokenAndGetClaims(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(key) // Set the key to verify the signature
                    .build()
                    .parseClaimsJws(token) // Parse and validate the token
                    .getBody(); // Get the claims payload
            return Optional.of(claims);
        } catch (ExpiredJwtException e) {
            log.warn("Token validation failed: Expired - {}", e.getMessage());
            return Optional.empty(); // Token expired
        } catch (UnsupportedJwtException e) {
            log.warn("Token validation failed: Unsupported - {}", e.getMessage());
            return Optional.empty(); // Token format not supported
        } catch (MalformedJwtException e) {
            log.warn("Token validation failed: Malformed - {}", e.getMessage());
            return Optional.empty(); // Token structure is invalid
        } catch (SignatureException e) {
            log.warn("Token validation failed: Invalid Signature - {}", e.getMessage());
            return Optional.empty(); // Signature doesn't match
        } catch (IllegalArgumentException e) {
            log.warn("Token validation failed: Illegal Argument - {}", e.getMessage());
            return Optional.empty(); // Other argument issues
        } catch (Exception e) { // Catch unexpected errors
            log.error("Unexpected error during token validation: {}", e.getMessage(), e);
            return Optional.empty();
        }
    }

    /**
     * Extracts a specific claim from the token using a resolver function.
     *
     * @param token          The JWT token string.
     * @param claimsResolver A function to extract the desired claim from the Claims object.
     * @param <T>            The type of the claim to extract.
     * @return An Optional containing the extracted claim value, or empty if extraction fails or token is invalid.
     */
    public <T> Optional<T> extractClaim(String token, Function<Claims, T> claimsResolver) {
        return validateTokenAndGetClaims(token).map(claimsResolver);
    }

    /**
     * Extracts the IP address claim ("ip") from the token.
     *
     * @param token The JWT token string.
     * @return An Optional containing the IP address, or empty if not present or token is invalid.
     */
    public Optional<String> extractIpAddress(String token) {
        // Use extractClaim with a lambda to get the "ip" claim as a String
        return extractClaim(token, claims -> claims.get("ip", String.class));
    }

    /**
     * Extracts the expiration date from the token.
     *
     * @param token The JWT token string.
     * @return An Optional containing the expiration Date, or empty if token is invalid.
     */
    public Optional<Date> extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Checks if the token is expired.
     *
     * @param token The JWT token string.
     * @return True if the token is expired, false otherwise (or if token is invalid).
     */
    public boolean isTokenExpired(String token) {
        // Check if the expiration date is before the current time
        return extractExpiration(token).map(exp -> exp.before(new Date())).orElse(true); // Treat invalid token as expired
    }


    // --- Helper method to convert hex string to byte array ---
    private byte[] hexStringToByteArray(String s) {
        int len = s.length();
        if (len % 2 != 0) {
             throw new IllegalArgumentException("Hex string must have an even number of characters.");
        }
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
}
