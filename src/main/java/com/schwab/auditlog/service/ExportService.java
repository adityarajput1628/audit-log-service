package com.schwab.auditlog.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.schwab.auditlog.crypto.HashChainEngine;
import com.schwab.auditlog.dto.ExportBundle;
import com.schwab.auditlog.dto.VerificationResult;
import com.schwab.auditlog.model.AuditRecord;
import com.schwab.auditlog.repository.AuditRecordRepository;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.*;

@Service
public class ExportService {

    private final AuditRecordRepository repository;
    private final HashChainEngine hashChainEngine;
    private final AuditLogService auditLogService;
    private final ObjectMapper objectMapper;

    public ExportService(AuditRecordRepository repository, HashChainEngine hashChainEngine, AuditLogService auditLogService, ObjectMapper objectMapper) {
        this.repository = repository;
        this.hashChainEngine = hashChainEngine;
        this.auditLogService = auditLogService;
        this.objectMapper = objectMapper;
    }

    /**
     * Generates a self-contained, verifiable export bundle for a resourceId or actorId.
     */
    @Transactional(readOnly = true)
    public ExportBundle generateExportBundle(String resourceId, String actorId) {
        if ((resourceId == null || resourceId.trim().isEmpty()) && (actorId == null || actorId.trim().isEmpty())) {
            throw new IllegalArgumentException("Must specify either resourceId or actorId for export.");
        }

        Specification<AuditRecord> spec = (root, query, cb) -> {
            if (resourceId != null && !resourceId.trim().isEmpty()) {
                return cb.equal(root.get("resourceId"), resourceId);
            } else {
                return cb.equal(root.get("actorId"), actorId);
            }
        };

        List<AuditRecord> records = repository.findAll(spec);
        records.sort(Comparator.comparing(AuditRecord::getSequenceNumber));

        VerificationResult verification = auditLogService.verifyChain();
        if (!verification.isIntact()) {
            throw new IllegalStateException("Export blocked: System audit chain is tampered or corrupted.");
        }

        List<Map<String, Object>> recordMaps = new ArrayList<>();
        StringBuilder bundleHashBuffer = new StringBuilder();

        for (AuditRecord r : records) {
            Map<String, Object> map = new HashMap<>();
            map.put("sequenceNumber", r.getSequenceNumber());
            map.put("eventType", r.getEventType());
            map.put("actorId", r.getActorId());
            map.put("resourceType", r.getResourceType());
            map.put("resourceId", r.getResourceId());
            try {
                map.put("payload", objectMapper.readValue(r.getPayloadJson(), new TypeReference<Map<String, Object>>() {}));
            } catch (Exception e) {
                map.put("payload", r.getPayloadJson());
            }
            map.put("timestamp", r.getTimestamp().toString());
            map.put("previousHash", r.getPreviousHash());
            map.put("recordHash", r.getRecordHash());
            map.put("archived", r.isArchived());

            recordMaps.add(map);
            bundleHashBuffer.append(r.getRecordHash());
        }

        String exportDigest = "HMAC-SHA256:" + hashChainEngine.hmacSha256(bundleHashBuffer.toString(), "SCHWAB_EXPORT_SECRET_KEY");
        String genesisHash = records.isEmpty() ? AuditRecord.GENESIS_HASH : records.get(0).getPreviousHash();
        String latestHash = records.isEmpty() ? AuditRecord.GENESIS_HASH : records.get(records.size() - 1).getRecordHash();

        return ExportBundle.builder()
                .exportId("EXP-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase())
                .exportedAt(Instant.now())
                .filterType(resourceId != null ? "resourceId" : "actorId")
                .filterValue(resourceId != null ? resourceId : actorId)
                .recordCount(records.size())
                .records(recordMaps)
                .exportDigest(exportDigest)
                .chainGenesisHash(genesisHash)
                .chainLatestHash(latestHash)
                .verificationStatus("VERIFIED_INTACT")
                .build();
    }
}
