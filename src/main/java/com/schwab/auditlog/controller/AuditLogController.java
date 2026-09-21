package com.schwab.auditlog.controller;

import com.schwab.auditlog.dto.*;
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
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/audit")
@CrossOrigin(origins = {"http://localhost:8080", "http://127.0.0.1:8080"})
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
        Page<AuditRecord> result = auditLogService.queryEvents(
                actorId, resourceType, resourceId, eventType, from, to, includeArchived, page, size);
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
     */
    @GetMapping("/export")
    public ResponseEntity<ExportBundle> exportBundle(
            @RequestParam(required = false) String resourceId,
            @RequestParam(required = false) String actorId
    ) {
        ExportBundle bundle = exportService.generateExportBundle(resourceId, actorId);
        return ResponseEntity.ok(bundle);
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
