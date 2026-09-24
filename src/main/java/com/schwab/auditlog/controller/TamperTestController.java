package com.schwab.auditlog.controller;

import com.schwab.auditlog.model.AuditRecord;
import com.schwab.auditlog.service.AuditLogService;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Isolated Demonstration Tamper Endpoint.
 * Strictly profile-gated to non-production environments (@Profile("!prod")).
 * Physically absent from the Spring ApplicationContext in production builds.
 */
@Profile("!prod")
@RestController
@RequestMapping("/api/v1/audit")
public class TamperTestController {

    private final AuditLogService auditLogService;

    public TamperTestController(AuditLogService auditLogService) {
        this.auditLogService = auditLogService;
    }

    /**
     * Live Tamper Simulator Endpoint for Demonstrations & Validation.
     * Mutates raw record in DB without recalculating recordHash to test detection.
     */
    @PostMapping("/tamper-test")
    public ResponseEntity<AuditRecord> simulateTampering(
            @RequestParam Long recordId,
            @RequestParam(required = false) String tamperedPayload,
            @RequestParam(required = false) String tamperedActorId
    ) {
        AuditRecord tampered = auditLogService.simulateTampering(recordId, tamperedPayload, tamperedActorId);
        return ResponseEntity.ok(tampered);
    }
}
