package com.schwab.auditlog.controller;

import com.schwab.auditlog.dto.*;
import com.schwab.auditlog.exception.AuditSecurityException;
import com.schwab.auditlog.model.AuditRecord;
import com.schwab.auditlog.service.AuditLogService;
import com.schwab.auditlog.service.ExportService;
import com.schwab.auditlog.service.RedactionService;
import com.schwab.auditlog.service.RetentionService;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/audit")
public class AuditLogController {

    private final AuditLogService auditLogService;
    private final RedactionService redactionService;
    private final RetentionService retentionService;
    private final ExportService exportService;

    public AuditLogController(
            AuditLogService auditLogService,
            RedactionService redactionService,
            RetentionService retentionService,
            ExportService exportService
    ) {
        this.auditLogService = auditLogService;
        this.redactionService = redactionService;
        this.retentionService = retentionService;
        this.exportService = exportService;
    }

    /**
     * Write API: Append-only event ingestion.
     */
    @PostMapping("/events")
    public ResponseEntity<AuditRecord> createEvent(@Valid @RequestBody CreateEventRequest request) {
        AuditRecord created = auditLogService.createEvent(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    /**
     * Query API: Multi-criteria filtering with pagination.
     * Enforces Resource & Tenant level authorization (BOLA/IDOR protection).
     */
    @GetMapping("/events")
    public ResponseEntity<Page<AuditRecord>> queryEvents(
            @RequestParam(required = false) String actorId,
            @RequestParam(required = false) String resourceType,
            @RequestParam(required = false) String resourceId,
            @RequestParam(required = false) String eventType,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to,
            @RequestParam(required = false, defaultValue = "false") Boolean includeArchived,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size
    ) {
        String effectiveActorId = validateResourceAuthorization(actorId);

        Page<AuditRecord> result = auditLogService.queryEvents(
                effectiveActorId, resourceType, resourceId, eventType, from, to, includeArchived, page, size);
        return ResponseEntity.ok(result);
    }

    /**
     * Chain Verification Endpoint: Walks full chain from genesis to HEAD.
     */
    @GetMapping("/verify")
    public ResponseEntity<VerificationResult> verifyChain() {
        VerificationResult result = auditLogService.verifyChain();
        return ResponseEntity.ok(result);
    }

    /**
     * Structured Redaction Endpoint: Redacts sensitive payload fields while preserving hash chain.
     */
    @PostMapping("/events/{id}/redact")
    public ResponseEntity<AuditRecord> redactField(
            @PathVariable Long id,
            @Valid @RequestBody RedactFieldRequest request
    ) {
        AuditRecord redacted = redactionService.redactPayloadField(id, request);
        return ResponseEntity.ok(redacted);
    }

    /**
     * Retention Policy Endpoint: Archives records older than configurable window.
     */
    @PostMapping("/retention/apply")
    public ResponseEntity<Map<String, Object>> applyRetention(@Valid @RequestBody RetentionRequest request) {
        Map<String, Object> result = retentionService.applyRetentionPolicy(request);
        return ResponseEntity.ok(result);
    }

    /**
     * Verifiable Bulk Export Endpoint: Self-contained JSON bundle with inclusion proof.
     * Enforces BOLA / IDOR resource authorization.
     */
    @GetMapping("/export")
    public ResponseEntity<ExportBundle> exportBundle(
            @RequestParam(required = false) String resourceId,
            @RequestParam(required = false) String actorId
    ) {
        String effectiveActorId = validateResourceAuthorization(actorId);
        ExportBundle bundle = exportService.generateExportBundle(resourceId, effectiveActorId);
        return ResponseEntity.ok(bundle);
    }

    /**


    /**
     * Helper to validate resource/tenant ownership (BOLA/IDOR protection).
     * If user is not ADMIN or AUDITOR, they can only query/export audit entries where actorId matches their username.
     */
    private String validateResourceAuthorization(String requestedActorId) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            return requestedActorId;
        }

        boolean isAdminOrAuditor = auth.getAuthorities().stream().anyMatch(a ->
                "ROLE_ADMIN".equals(a.getAuthority()) || "ROLE_AUDITOR".equals(a.getAuthority()));

        if (isAdminOrAuditor) {
            return requestedActorId;
        }

        String currentUsername = auth.getName();
        if (requestedActorId != null && !requestedActorId.trim().isEmpty() && !requestedActorId.equals(currentUsername)) {
            throw new AuditSecurityException("Access Denied: BOLA/IDOR protection policy prevents non-auditors from viewing audit records for actorId: " + requestedActorId);
        }

        return currentUsername;
    }
}

