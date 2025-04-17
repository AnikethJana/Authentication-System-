package com.aniketh.app.controller;

import java.util.Collections;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

import com.aniketh.app.dto.AuthResponse;
import com.aniketh.app.dto.StateResponse;
import com.aniketh.app.dto.TokenRequest;
import com.aniketh.app.service.AuthService;
import com.aniketh.app.service.IpAddressService;
import com.aniketh.app.service.StateTokenService;
import com.aniketh.app.util.CookieUtil;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;

/**
 * REST Controller handling authentication endpoints.
 */
@RestController
@RequestMapping("/api/auth") // Base path for all auth endpoints
// CrossOrigin annotation handled globally in WebConfig
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);
    private static final String UNKNOWN_IP = "UNKNOWN";

    @Autowired
    private AuthService authService;

    @Autowired
    private StateTokenService stateTokenService;

    @Autowired
    private IpAddressService ipAddressService;

    @Autowired
    private CookieUtil cookieUtil;

    @Value("${frontend.redirect.baseurl:http://localhost:5500}") // Default for local dev
    private String frontendBaseUrl; // Base URL of the frontend application for redirects


    /**
     * GET /api/auth/initiate-auth
     * Initiates the authentication flow by generating and storing a state token.
     *
     * @param request HttpServletRequest to get client IP.
     * @return ResponseEntity containing the state token or an error.
     */
    @GetMapping("/initiate-auth")
    public ResponseEntity<StateResponse> initiateAuth(HttpServletRequest request) {
        String clientIp = ipAddressService.getClientIpAddress(request);
        if (UNKNOWN_IP.equals(clientIp)) {
            log.error("Initiate-auth failed: Could not determine client IP.");
            return ResponseEntity.badRequest().body(new StateResponse(false, null, "Could not determine client IP address."));
        }

        // Generate state token (can include params if needed, pass Collections.emptyMap() for none)
        String stateToken = stateTokenService.createStateToken(Collections.emptyMap());

        if (stateTokenService.storeStateToken(clientIp, stateToken)) {
            log.info("Initiated auth for IP: {}, State token generated.", clientIp);
            return ResponseEntity.ok(new StateResponse(true, stateToken, null));
        } else {
            log.error("Initiate-auth failed: Could not store state token for IP: {}", clientIp);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new StateResponse(false, null, "Internal server error during auth initiation."));
        }
    }

    /**
     * GET /api/auth/check-auth
     * Checks the current authentication status via cookie or IP session.
     * Handles token refresh and IP changes automatically.
     *
     * @param request  HttpServletRequest.
     * @param response HttpServletResponse.
     * @return ResponseEntity containing the authentication status.
     */
    @GetMapping("/check-auth")
    public ResponseEntity<AuthResponse> checkAuth(HttpServletRequest request, HttpServletResponse response) {
        String clientIp = ipAddressService.getClientIpAddress(request);
        if (UNKNOWN_IP.equals(clientIp)) {
             log.error("Check-auth failed: Could not determine client IP.");
            return ResponseEntity.badRequest().body(new AuthResponse(false, "Could not determine client IP."));
        }

        // Referrer check removed as per requirement ("let it be *") - CORS handles origin control.

        AuthResponse authResult = authService.checkAuthentication(request, response, clientIp);

        if (authResult.getAuthenticated()) {
            return ResponseEntity.ok(authResult);
        } else {
            // Return 401 Unauthorized if authentication failed
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(authResult);
        }
    }

    /**
     * POST /api/auth/verify-token
     * Verifies a token provided in the request body against the current client IP.
     *
     * @param tokenRequest DTO containing the token.
     * @param request      HttpServletRequest.
     * @return ResponseEntity indicating verification status.
     */
    @PostMapping("/verify-token")
    public ResponseEntity<AuthResponse> verifyToken(@Valid @RequestBody TokenRequest tokenRequest, HttpServletRequest request) {
         String clientIp = ipAddressService.getClientIpAddress(request);
        if (UNKNOWN_IP.equals(clientIp)) {
             log.error("Verify-token failed: Could not determine client IP.");
            return ResponseEntity.badRequest().body(new AuthResponse(false, "Could not determine client IP."));
        }

        AuthResponse verificationResult = authService.verifyTokenStrict(tokenRequest.getToken(), clientIp);

        if (verificationResult.getAuthenticated()) {
            return ResponseEntity.ok(verificationResult);
        } else {
            // Return 401 Unauthorized if verification failed
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(verificationResult);
        }
    }

    /**
     * GET /api/auth/auth-callback
     * Handles the redirect back from an external process (e.g., OAuth provider, or just a simulated step or potential revenue implementation).
     * Verifies the state parameter, generates a JWT, sets the cookie, and redirects to the frontend.
     *
     * @param state    The state token received from the callback query parameter.
     * @param request  HttpServletRequest.
     * @param response HttpServletResponse.
     * @return ResponseEntity performing a redirect or showing an error.
     */
    @GetMapping("/auth-callback")
    public ResponseEntity<Void> authCallback(@RequestParam(name = "state", required = false) String state,
                                             HttpServletRequest request, HttpServletResponse response) {
        String clientIp = ipAddressService.getClientIpAddress(request);
        if (UNKNOWN_IP.equals(clientIp)) {
            log.error("Auth-callback failed: Could not determine client IP.");
            // Cannot easily return JSON here as it's a redirect endpoint.
            // Redirect to an error page or return a simple error status.
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }

        if (state == null || state.isEmpty()) {
             log.error("Auth-callback failed: Missing state parameter for IP: {}", clientIp);
             return ResponseEntity.status(HttpStatus.BAD_REQUEST).build(); // Or redirect to an error page
        }

        // Verify and consume the state token
        if (!stateTokenService.verifyAndConsumeStateToken(clientIp, state)) {
            log.error("Auth-callback failed: Invalid or expired state token for IP: {}. State: '{}'", clientIp, state);
             // Redirect to frontend error page or return error status
             String errorRedirectUrl = UriComponentsBuilder.fromHttpUrl(frontendBaseUrl)
                                        .path("/auth-error") // Example error path
                                        .queryParam("error", "invalid_state")
                                        .toUriString();
             response.setHeader("Location", errorRedirectUrl);
             return ResponseEntity.status(HttpStatus.FOUND).build(); // 302 Found for redirect
        }

        // State is valid, proceed with authentication:
        // 1. Extract original parameters if they were encoded in the state
        Map<String, String> originalParams = stateTokenService.extractOriginalParams(state);
        log.debug("Original params extracted from state: {}", originalParams);

        // 2. Generate new JWT, set cookie
        String newToken = authService.refreshTokenAndCookie(clientIp, response);

        // 3. Store the session info (IP/New Token)
        if (!authService.storeSession(clientIp, newToken)) {
            log.error("Auth-callback warning: Failed to store session after successful auth for IP: {}", clientIp);
            // Decide if this is critical. Cookie is set, so user might still be logged in.
            // Maybe redirect with a warning parameter?
        }

        // 4. Prepare redirect URL back to the frontend
        UriComponentsBuilder redirectBuilder = UriComponentsBuilder.fromHttpUrl(frontendBaseUrl)
                .path("/") // Or a specific path like "/dashboard"
                .queryParam("auth-return", "true"); // Indicate successful auth

        // Add original parameters back to the redirect URL
        originalParams.forEach(redirectBuilder::queryParam);

        String redirectUrl = redirectBuilder.toUriString();
        log.info("Auth-callback successful for IP: {}. Redirecting to: {}", clientIp, redirectUrl);

        // Perform Redirect
        response.setHeader("Location", redirectUrl);
        return ResponseEntity.status(HttpStatus.FOUND).build(); // 302 Found
    }
}
