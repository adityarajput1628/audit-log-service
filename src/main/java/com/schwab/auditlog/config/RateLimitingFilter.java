package com.schwab.auditlog.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Application-Level Rate Limiter Filter (Phase 7).
 * Prevents ingestion & verification endpoint abuse using sliding window token buckets per client IP.
 */
@Component
public class RateLimitingFilter extends OncePerRequestFilter {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Map<String, TokenBucket> buckets = new ConcurrentHashMap<>();
    private final int MAX_TOKENS = 120; // 120 requests
    private final long REFILL_WINDOW_MILLIS = 60_000; // 1 minute

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getRequestURI();
        if (path.startsWith("/api/v1/audit/events") || path.startsWith("/api/v1/audit/checkpoint")) {
            String clientIp = getClientIp(request);
            TokenBucket bucket = buckets.computeIfAbsent(clientIp, k -> new TokenBucket(MAX_TOKENS, REFILL_WINDOW_MILLIS));

            if (!bucket.tryConsume()) {
                response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                response.setHeader("Retry-After", "60");

                Map<String, Object> errorDetails = Map.of(
                        "timestamp", Instant.now().toString(),
                        "status", 429,
                        "error", "Too Many Requests",
                        "message", "Rate limit exceeded. Maximum 120 requests per minute allowed.",
                        "path", path
                );
                objectMapper.writeValue(response.getOutputStream(), errorDetails);
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private String getClientIp(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader != null && !xfHeader.isEmpty()) {
            return xfHeader.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    private static class TokenBucket {
        private final int capacity;
        private final long refillIntervalMillis;
        private int tokens;
        private long lastRefillTime;

        public TokenBucket(int capacity, long refillIntervalMillis) {
            this.capacity = capacity;
            this.refillIntervalMillis = refillIntervalMillis;
            this.tokens = capacity;
            this.lastRefillTime = System.currentTimeMillis();
        }

        public synchronized boolean tryConsume() {
            refill();
            if (tokens > 0) {
                tokens--;
                return true;
            }
            return false;
        }

        private void refill() {
            long now = System.currentTimeMillis();
            if (now - lastRefillTime > refillIntervalMillis) {
                tokens = capacity;
                lastRefillTime = now;
            }
        }
    }
}
