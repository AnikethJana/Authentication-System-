package com.aniketh.app.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Configuration class for Spring Web MVC settings, including CORS.
 */
@Configuration
public class WebConfig implements WebMvcConfigurer {

    private static final Logger log = LoggerFactory.getLogger(WebConfig.class);

    /**
     * Configures Cross-Origin Resource Sharing (CORS) globally for the application.
     * Allows all origins ("*") for development/testing purposes as requested.
     * Allows common HTTP methods and headers, and credentials (cookies).
     *
     * IMPORTANT: For production, restrict allowedOrigins to your specific frontend domain(s).
     * e.g., .allowedOrigins("https://your-domain.com")
     */
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        log.warn("Configuring CORS to allow all origins ('*'). THIS IS NOT RECOMMENDED FOR PRODUCTION.");
        registry.addMapping("/api/**") // Apply CORS to paths starting with /api
                .allowedOriginPatterns("*") // Allow requests from any origin (USE SPECIFIC DOMAIN IN PRODUCTION!)
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS") // Allowed HTTP methods
                .allowedHeaders("*") // Allow all headers
                .allowCredentials(true) // Allow cookies and authorization headers
                .maxAge(3600); // Cache preflight response for 1 hour
    }

     // Optional: You can define other WebMvcConfigurer beans here if needed.
}
