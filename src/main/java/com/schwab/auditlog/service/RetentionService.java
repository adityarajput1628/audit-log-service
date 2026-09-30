package com.schwab.auditlog.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.schwab.auditlog.dto.CreateEventRequest;
import com.schwab.auditlog.dto.RetentionRequest;
import com.schwab.auditlog.model.AuditRecord;
import com.schwab.auditlog.repository.AuditRecordRepository;
import com.schwab.auditlog.security.SecurityEventLogger;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Service
public class RetentionService {

    private final AuditRecordRepository repository;
    private final AuditLogService auditLogService;
    private final ObjectMapper objectMapper;
    private final SecurityEventLogger securityEventLogger;

    public RetentionService(
            AuditRecordRepository repository,
            AuditLogService auditLogService,
            ObjectMapper objectMapper,
            SecurityEventLogger securityEventLogger
    ) {
        this.repository = repository;
        this.auditLogService = auditLogService;
        this.objectMapper = objectMapper;
        this.securityEventLogger = securityEventLogger;
    }

    /**
     * Applies append-only retention policy without mutating historical audit record hashes or payloads.
     * Appends explicit RETENTION_TOMBSTONE events to the immutable audit chain.
     */
    @Transactional
    public Map<String, Object> applyRetentionPolicy(RetentionRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("RetentionRequest cannot be null");
        }

        int windowDays = Math.max(request.getRetentionWindowDays(), 0);
        Instant cutoff = Instant.now().minus(windowDays, ChronoUnit.DAYS);

        Specification<AuditRecord> spec = (root, query, cb) -> cb.and(
                cb.lessThanOrEqualTo(root.get("timestamp"), cutoff),
                cb.equal(root.get("archived"), false)
        );

        List<AuditRecord> eligibleRecords = repository.findAll(spec);

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String currentActor = (auth != null && auth.getName() != null) ? auth.getName() : "SYSTEM_RETENTION_SERVICE";

        if (request.isDryRun()) {
            Map<String, Object> response = new LinkedHashMap<>();
            response.put("dryRun", true);
            response.put("eligibleCount", eligibleRecords.size());
            response.put("cutoffTimestamp", cutoff.toString());
            return response;
        }

        Instant archivedAt = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        int archivedCount = 0;
        List<Long> tombstonedSequenceNumbers = new ArrayList<>();

        for (AuditRecord targetRecord : eligibleRecords) {
            // Mark archived flag without altering original payloadJson, actorId, timestamp, or recordHash
            targetRecord.setArchived(true);
            targetRecord.setArchivedAt(archivedAt);
            repository.save(targetRecord);

            // Append a new RETENTION_TOMBSTONE event to the immutable chain
            Map<String, Object> tombstonePayload = new LinkedHashMap<>();
            tombstonePayload.put("targetRecordId", targetRecord.getId());
            tombstonePayload.put("targetSequenceNumber", targetRecord.getSequenceNumber());
            tombstonePayload.put("targetOriginalHash", targetRecord.getRecordHash());
            tombstonePayload.put("retentionWindowDays", request.getRetentionWindowDays());
            tombstonePayload.put("retentionTimestamp", archivedAt.toString());
            tombstonePayload.put("reason", "AUTOMATED_RETENTION_POLICY");

            CreateEventRequest tombstoneEventRequest = CreateEventRequest.builder()
                    .eventType("RETENTION_TOMBSTONE")
                    .actorId(currentActor)
                    .resourceType(targetRecord.getResourceType())
                    .resourceId(targetRecord.getResourceId())
                    .payload(tombstonePayload)
                    .build();

            auditLogService.createEventInternal(tombstoneEventRequest, null, true);
            archivedCount++;
            tombstonedSequenceNumbers.add(targetRecord.getSequenceNumber());
        }

        securityEventLogger.logSecurityEvent(
                SecurityEventLogger.EventCategory.RETENTION_EXECUTION,
                currentActor,
                "APPLY_RETENTION_POLICY",
                "RETENTION_SERVICE",
                "SUCCESS",
                "Archived " + archivedCount + " records older than cutoff " + cutoff,
                Map.of("archivedCount", archivedCount, "tombstonedSequences", tombstonedSequenceNumbers)
        );

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("dryRun", false);
        response.put("archivedCount", archivedCount);
        response.put("cutoffTimestamp", cutoff.toString());
        response.put("status", "Retention policy executed successfully with append-only tombstones.");
        return response;
    }
}
