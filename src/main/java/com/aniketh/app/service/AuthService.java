package com.aniketh.app.service;

import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.aniketh.app.dto.AuthResponse;
import com.aniketh.app.entity.AuthSession;
import com.aniketh.app.repository.AuthSessionRepository;
import com.aniketh.app.util.CookieUtil;

import io.jsonwebtoken.Claims;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Main service handling authentication logic, session management, and token operations.
 */
@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    @Autowired
    private AuthSessionRepository authSessionRepository;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private CookieUtil cookieUtil;

    @Value("${jwt.cookie.name}")
    private String cookieName;

    @Value("${jwt.expiration.ms}")
    private long authDurationMs; // Use the same expiration as JWT

    /**
     * Checks the authentication status based on JWT cookie or IP session.
     * Handles token validation, IP mismatches, session refresh, and cookie updates.
     *
     * @param request  The incoming HttpServletRequest.
     * @param response The outgoing HttpServletResponse (for setting cookies).
     * @param clientIp The determined client IP address.
     * @return AuthResponse indicating authentication status and method.
     */
    @Transactional // Ensure DB operations are atomic within this method
    public AuthResponse checkAuthentication(HttpServletRequest request, HttpServletResponse response, String clientIp) {
        Cookie authCookie = cookieUtil.getCookie(request, cookieName);
        String tokenFromCookie = (authCookie != null) ? authCookie.getValue() : null;
        String verificationError = null;
        boolean authenticated = false;
        String method = "none";

        // 1. Check JWT from Cookie
        if (tokenFromCookie != null) {
            Optional<Claims> claimsOptional = jwtService.validateTokenAndGetClaims(tokenFromCookie);

            if (claimsOptional.isPresent()) {
                Claims claims = claimsOptional.get();
                String tokenIp = claims.get("ip", String.class);

                if (tokenIp != null && tokenIp.equals(clientIp)) {
                    // Token valid and IP matches
                    authenticated = true;
                    method = "token";
                    log.debug("Auth check successful via valid token for IP: {}", clientIp);
                    // Optional: Refresh token/cookie expiry if needed on activity
                    //refreshTokenAndCookie(clientIp, response);

                } else if (tokenIp != null) {
                    // Token valid BUT IP mismatch - Refresh token and session for the new IP
                    log.warn("Valid token found but IP mismatch. Old IP: {}, New IP: {}. Refreshing session.", tokenIp, clientIp);
                    String newToken = refreshTokenAndCookie(clientIp, response);
                    storeSession(clientIp, newToken); // Store new token for new IP
                    authenticated = true;
                    method = "token_ip_updated";
                } else {
                     // Valid token structure but missing IP claim - treat as invalid for this logic
                     verificationError = "Token missing IP claim";
                     log.warn("Token validation failed: {} for IP: {}", verificationError, clientIp);
                     cookieUtil.deleteCookie(response, cookieName); // Delete invalid cookie
                }

            } else {
                // Token validation failed (expired, signature invalid, etc.)
                verificationError = "Invalid or expired token"; // More specific errors logged by JwtService
                log.warn("Token validation failed: {} for IP: {}", verificationError, clientIp);
                cookieUtil.deleteCookie(response, cookieName); // Delete invalid cookie
            }
        }

        // 2. If not authenticated via cookie, check DB session for the current IP
        if (!authenticated) {
            log.debug("No valid token found or token verification failed for IP: {}. Checking DB session.", clientIp);
            Optional<AuthSession> sessionOptional = authSessionRepository.findByIpAddress(clientIp);

            if (sessionOptional.isPresent()) {
                AuthSession session = sessionOptional.get();
                long sessionTimestamp = session.getTimestamp();
                long nowSeconds = System.currentTimeMillis() / 1000;
                long authDurationSeconds = authDurationMs / 1000;

                if ((nowSeconds - sessionTimestamp) < authDurationSeconds) {
                    // Found valid, non-expired DB session for this IP. Issue a new token/cookie.
                    log.info("Found active DB session for IP: {}. Issuing new token.", clientIp);
                    String newToken = refreshTokenAndCookie(clientIp, response);
                    // Update the session in DB with the new token and timestamp
                    session.setToken(newToken);
                    // session.setTimestamp(nowSeconds); // @PreUpdate handles this
                    authSessionRepository.save(session);
                    authenticated = true;
                    method = "ip_refresh";
                } else {
                    // DB session exists but is expired
                    log.warn("Found expired DB session for IP: {}. Deleting.", clientIp);
                    authSessionRepository.delete(session); // Clean up expired session
                    verificationError = verificationError != null ? verificationError : "Expired DB session";
                }
            } else {
                 // No session found in DB for this IP
                 verificationError = verificationError != null ? verificationError : "No valid session found";
                 log.debug("No active DB session found for IP: {}", clientIp);
            }
        }

        // Build response DTO
        AuthResponse authResponse = new AuthResponse(authenticated);
        authResponse.setMethod(method);
        if (!authenticated) {
            authResponse.setReason(verificationError);
        }
        return authResponse;
    }

     /**
     * Verifies a token provided explicitly (e.g., in request body).
     * Requires strict IP matching between the token and the current client IP.
     *
     * @param token    The token string to verify.
     * @param clientIp The current client IP address.
     * @return AuthResponse indicating verification status.
     */
     public AuthResponse verifyTokenStrict(String token, String clientIp) {
         if (token == null || token.isEmpty()) {
             return new AuthResponse(false, "none", "Token required");
         }

         Optional<Claims> claimsOptional = jwtService.validateTokenAndGetClaims(token);

         if (claimsOptional.isPresent()) {
             Claims claims = claimsOptional.get();
             String tokenIp = claims.get("ip", String.class);

             if (tokenIp != null && tokenIp.equals(clientIp)) {
                 log.debug("Strict token verification successful for IP: {}", clientIp);
                 return new AuthResponse(true, "token_verified", null);
             } else if (tokenIp != null) {
                 log.warn("/verify-token IP mismatch. Token IP: {}, Client IP: {}", tokenIp, clientIp);
                 return new AuthResponse(false, "none", "Token valid but IP mismatch for verification");
             } else {
                  log.warn("/verify-token failed: Token missing IP claim for IP: {}", clientIp);
                  return new AuthResponse(false, "none", "Token missing IP claim");
             }
         } else {
             log.warn("/verify-token failed: Invalid or expired token for IP: {}", clientIp);
             return new AuthResponse(false, "none", "Invalid or expired token");
         }
     }


    /**
     * Stores or updates the IP address and associated JWT token in the database.
     *
     * @param ipAddress The client's IP address.
     * @param token     The JWT token.
     * @return true on success, false on failure.
     */
    @Transactional
    public boolean storeSession(String ipAddress, String token) {
        try {
            // Create or update the session. save() handles both cases based on ID existence.
            AuthSession session = new AuthSession(ipAddress, token, System.currentTimeMillis() / 1000);
            authSessionRepository.save(session);
            log.debug("Stored/Updated session for IP: {}", ipAddress);
            return true;
        } catch (Exception e) {
            log.error("Failed to store session for IP {}: {}", ipAddress, e.getMessage(), e);
            return false;
        }
    }

    /**
     * Generates a new JWT for the IP, sets it in the response cookie.
     *
     * @param ipAddress The client's IP address.
     * @param response  The HttpServletResponse to set the cookie on.
     * @return The newly generated token string.
     */
    public String refreshTokenAndCookie(String ipAddress, HttpServletResponse response) {
        String newToken = jwtService.generateToken(ipAddress);
        cookieUtil.setCookie(response, cookieName, newToken, (int) (authDurationMs / 1000));
        log.debug("Refreshed token and set cookie for IP: {}", ipAddress);
        return newToken;
    }
}