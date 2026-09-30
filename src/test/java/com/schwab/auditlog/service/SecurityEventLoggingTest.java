package com.schwab.auditlog.service;

import com.schwab.auditlog.security.SecurityEventLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

@SpringBootTest
@ActiveProfiles("test")
public class SecurityEventLoggingTest {

    @Autowired
    private SecurityEventLogger securityEventLogger;

    @Test
    @DisplayName("Phase 8: SecurityEventLogger logs structured security events cleanly without throwing exceptions")
    void testStructuredSecurityLogging() {
        assertDoesNotThrow(() -> {
            securityEventLogger.logSecurityEvent(
                    SecurityEventLogger.EventCategory.ACTOR_SPOOF_ATTEMPT,
                    "malicious_user",
                    "CREATE_EVENT",
                    "ACCOUNT:123",
                    "DENIED",
                    "Attempted to impersonate admin_user",
                    Map.of("ip", "10.0.0.99", "password", "SECRET_WOULD_BE_FILTERED")
            );

            securityEventLogger.logSecurityEvent(
                    SecurityEventLogger.EventCategory.CHECKPOINT_EVENT,
                    "SYSTEM",
                    "CREATE_CHECKPOINT",
                    "CHAIN_HEAD",
                    "SUCCESS",
                    "Checkpoint created",
                    Map.of("checkpointId", "CHK-TEST-1")
            );
        });
    }
}
