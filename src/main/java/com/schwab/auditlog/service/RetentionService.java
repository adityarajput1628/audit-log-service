package com.schwab.auditlog.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.schwab.auditlog.crypto.HashChainEngine;
import com.schwab.auditlog.dto.RetentionRequest;
import com.schwab.auditlog.model.AuditRecord;
import com.schwab.auditlog.repository.AuditRecordRepository;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Service
public class RetentionService {

    private final AuditRecordRepository repository;
    private final HashChainEngine hashChainEngine;
    private final ObjectMapper objectMapper;

    public RetentionService(AuditRecordRepository repository, HashChainEngine hashChainEngine, ObjectMapper objectMapper) {
        this.repository = repository;
        this.hashChainEngine = hashChainEngine;
        this.objectMapper = objectMapper;
    }

    /**
     * Applies retention policy archiving records older than specified window days.
     */
    @Transactional
    public Map<String, Object> applyRetentionPolicy(RetentionRequest request) {
        Instant cutoff = Instant.now().minus(request.getRetentionWindowDays(), ChronoUnit.DAYS);

        Specification<AuditRecord> spec = (root, query, cb) -> cb.and(
                cb.lessThan(root.get("timestamp"), cutoff),
                cb.equal(root.get("archived"), false)
        );

        List<AuditRecord> eligibleRecords = repository.findAll(spec);

        if (request.isDryRun()) {
            Map<String, Object> response = new HashMap<>();
            response.put("dryRun", true);
            response.put("eligibleCount", eligibleRecords.size());
            response.put("cutoffTimestamp", cutoff.toString());
            return response;
        }

        Instant archivedAt = Instant.now();
        int archivedCount = 0;

        for (AuditRecord record : eligibleRecords) {
            record.setArchived(true);
            record.setArchivedAt(archivedAt);

            // Preserve original payload hash prior to tombstoning
            String originalPayloadHash = hashChainEngine.calculatePayloadHash(
                    record.getPayloadJson(), record.getRedactionsJson(), record.getPreviousHash());

            Map<String, HashChainEngine.RedactionEntry> redactionsMap = new HashMap<>();
            if (record.getRedactionsJson() != null && !record.getRedactionsJson().trim().isEmpty()) {
                try {
                    redactionsMap = objectMapper.readValue(record.getRedactionsJson(), new com.fasterxml.jackson.core.type.TypeReference<>() {});
                } catch (Exception ignored) {}
            }
            redactionsMap.put("_ARCHIVED_PAYLOAD", new HashChainEngine.RedactionEntry("ARCHIVED_SALT", originalPayloadHash));

            try {
                record.setRedactionsJson(objectMapper.writeValueAsString(redactionsMap));
            } catch (Exception ignored) {}

            // Create tombstone payload summary preserving chain metadata
            Map<String, Object> tombstonePayload = new HashMap<>();
            tombstonePayload.put("_archived", true);
            tombstonePayload.put("_archivedAt", archivedAt.toString());
            tombstonePayload.put("_retentionWindowDays", request.getRetentionWindowDays());

            try {
                record.setPayloadJson(objectMapper.writeValueAsString(tombstonePayload));
            } catch (Exception ignored) {}

            repository.save(record);
            archivedCount++;
        }

        Map<String, Object> response = new HashMap<>();
        response.put("dryRun", false);
        response.put("archivedCount", archivedCount);
        response.put("cutoffTimestamp", cutoff.toString());
        response.put("status", "Retention policy executed successfully.");
        return response;
    }
}
