package com.schwab.auditlog.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.schwab.auditlog.security.AccountLockoutService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;

/**
 * Filter checking for locked out usernames before authenticating requests.
 * Returns HTTP 423 Locked when a username has 5 consecutive failed authentication attempts.
 */
@Component
public class AccountLockoutFilter extends OncePerRequestFilter {

    private final AccountLockoutService lockoutService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public AccountLockoutFilter(AccountLockoutService lockoutService) {
        this.lockoutService = lockoutService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Basic ")) {
            String username = extractUsername(authHeader);
            if (username != null && lockoutService.isLocked(username)) {
                response.setStatus(HttpStatus.LOCKED.value()); // 423
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                Map<String, Object> errorDetails = Map.of(
                        "timestamp", Instant.now().toString(),
                        "status", 423,
                        "error", "Locked",
                        "message", "Account locked due to 5 consecutive failed authentication attempts. Please try again after 15 minutes.",
                        "path", request.getRequestURI()
                );
                objectMapper.writeValue(response.getOutputStream(), errorDetails);
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private String extractUsername(String authHeader) {
        try {
            String base64Credentials = authHeader.substring(6).trim();
            byte[] credBytes = Base64.getDecoder().decode(base64Credentials);
            String credentials = new String(credBytes, StandardCharsets.UTF_8);
            String[] values = credentials.split(":", 2);
            return values.length > 0 ? values[0] : null;
        } catch (Exception e) {
            return null;
        }
    }
}
