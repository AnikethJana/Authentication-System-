package com.aniketh.app.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Service to retrieve the client's IP address from the HttpServletRequest.
 * Considers common proxy headers like X-Forwarded-For.
 */
@Service
public class IpAddressService {

    private static final Logger log = LoggerFactory.getLogger(IpAddressService.class);
    private static final String UNKNOWN_IP = "UNKNOWN";
    private static final String[] IP_HEADER_CANDIDATES = {
            "X-Forwarded-For",
            "Proxy-Client-IP",
            "WL-Proxy-Client-IP",
            "HTTP_X_FORWARDED_FOR",
            "HTTP_X_FORWARDED",
            "HTTP_X_CLUSTER_CLIENT_IP",
            "HTTP_CLIENT_IP",
            "HTTP_FORWARDED_FOR",
            "HTTP_FORWARDED",
            "HTTP_VIA",
            "REMOTE_ADDR" // Fallback
    };

    /**
     * Gets the client IP address from the request, checking proxy headers.
     *
     * @param request The HttpServletRequest object.
     * @return The client's IP address or "UNKNOWN" if not determinable.
     */
    public String getClientIpAddress(HttpServletRequest request) {
        if (request == null) {
            log.warn("HttpServletRequest is null, cannot determine IP address.");
            return UNKNOWN_IP;
        }

        for (String header : IP_HEADER_CANDIDATES) {
            String ipList = request.getHeader(header);
            // Check if the header exists and is not empty or "unknown" (case-insensitive)
            if (StringUtils.hasText(ipList) && !"unknown".equalsIgnoreCase(ipList)) {
                // X-Forwarded-For can contain a comma-separated list of IPs (client, proxy1, proxy2)
                // The first IP in the list is generally the original client IP.
                String ip = ipList.split(",")[0].trim();
                 log.debug("IP found via header '{}': {}", header, ip);
                return ip;
            }
        }

        // If no headers found, use the direct remote address
        String remoteAddr = request.getRemoteAddr();
         log.debug("No specific IP header found, using request.getRemoteAddr(): {}", remoteAddr);
        return StringUtils.hasText(remoteAddr) ? remoteAddr : UNKNOWN_IP;
    }
}