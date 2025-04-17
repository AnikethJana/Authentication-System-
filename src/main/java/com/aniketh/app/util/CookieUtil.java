package com.aniketh.app.util;

import org.springframework.stereotype.Component;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Utility class for handling HTTP Cookies.
 */
@Component
public class CookieUtil {

    /**
     * Sets an HTTP cookie with secure attributes.
     *
     * @param response The HttpServletResponse to add the cookie to.
     * @param name     The name of the cookie.
     * @param value    The value of the cookie.
     * @param maxAge   The maximum age in seconds. Use -1 to delete, 0 for session cookie.
     */
    public void setCookie(HttpServletResponse response, String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true); // Prevent access via JavaScript
        cookie.setSecure(true);   // Transmit only over HTTPS
        cookie.setPath("/");      // Available across the entire domain
        cookie.setMaxAge(maxAge); // Set expiration time
        // SameSite=None requires Secure=true. Use Lax or Strict if appropriate for your use case.
        // For cross-site requests (like API on different domain than frontend), None is often needed.
        cookie.setAttribute("SameSite", "None");
        // cookie.setDomain("yourdomain.com"); // Set specific domain in production if needed

        response.addCookie(cookie);
    }

    /**
     * Retrieves a cookie by name from the request.
     *
     * @param request The HttpServletRequest containing the cookies.
     * @param name    The name of the cookie to retrieve.
     * @return The Cookie object if found, otherwise null.
     */
    public Cookie getCookie(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (name.equals(cookie.getName())) {
                    return cookie;
                }
            }
        }
        return null;
    }

    /**
     * Deletes a cookie by setting its max age to 0.
     * Ensures path and domain match the original cookie if set.
     *
     * @param response The HttpServletResponse to modify the cookie on.
     * @param name     The name of the cookie to delete.
     */
    public void deleteCookie(HttpServletResponse response, String name) {
         // Create a cookie with the same name, path, and potentially domain,
         // but with an empty value and maxAge of 0.
         Cookie cookie = new Cookie(name, null); // Value can be null or empty
         cookie.setHttpOnly(true);
         cookie.setSecure(true);
         cookie.setPath("/");
         cookie.setMaxAge(0); // Set max age to 0 to expire immediately
         cookie.setAttribute("SameSite", "None"); // Match SameSite attribute
         // cookie.setDomain("yourdomain.com"); // Match domain if it was set

         response.addCookie(cookie);
    }
}
