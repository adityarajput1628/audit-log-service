package com.schwab.auditlog.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

@Component
public class SecurityEventLogger {

    private static final Logger log = LoggerFactory.getLogger("SECURITY_AUDIT_LOG");
    private final ObjectMapper objectMapper = new ObjectMapper();

    public enum EventCategory {
        AUTHENTICATION_FAILURE,
        AUTHORIZATION_FAILURE,
        BOLA_ATTEMPT,
        ACTOR_SPOOF_ATTEMPT,
        INVALID_REQUEST,
        INTEGRITY_VERIFICATION_FAILURE,
        RETENTION_EXECUTION,
        CHECKPOINT_EVENT
    }

    public void logSecurityEvent(
            EventCategory category,
            String principal,
            String action,
            String targetResource,
            String outcome,
            String reason,
            Map<String, Object> additionalContext
    ) {
        try {
            Map<String, Object> event = new LinkedHashMap<>();
            event.put("timestamp", Instant.now().toString());
            event.put("eventCategory", category.name());
            event.put("principal", principal != null ? principal : "ANONYMOUS");
            event.put("action", action);
            event.put("targetResource", targetResource != null ? targetResource : "N/A");
            event.put("outcome", outcome);
            event.put("reason", reason);

            if (additionalContext != null && !additionalContext.isEmpty()) {
                // Ensure no secrets or credentials are logged
                Map<String, Object> safeContext = new LinkedHashMap<>(additionalContext);
                safeContext.remove("password");
                safeContext.remove("secret");
                safeContext.remove("token");
                safeContext.remove("authorization");
                event.put("context", safeContext);
            }

            String logJson = objectMapper.writeValueAsString(event);
            if ("FAILURE".equalsIgnoreCase(outcome) || "DENIED".equalsIgnoreCase(outcome)) {
                log.warn("SECURITY_EVENT: {}", logJson);
            } else {
                log.info("SECURITY_EVENT: {}", logJson);
            }
        } catch (Exception e) {
            log.error("Failed to format security event log", e);
        }
    }
}
