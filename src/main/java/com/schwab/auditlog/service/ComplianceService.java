package com.schwab.auditlog.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.schwab.auditlog.crypto.HashChainEngine;
import com.schwab.auditlog.dto.ComplianceReport;
import com.schwab.auditlog.dto.ComplianceReport.ActorAccessSummary;
import com.schwab.auditlog.dto.VerificationResult;
import com.schwab.auditlog.model.AuditRecord;
import com.schwab.auditlog.repository.AuditRecordRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class ComplianceService {

    private final AuditRecordRepository repository;
    private final HashChainEngine hashChainEngine;
    private final AuditLogService auditLogService;
    private final ObjectMapper objectMapper;

    @Value("${schwab.security.hmac.secret}")
    private String hmacSecret;

    public ComplianceService(AuditRecordRepository repository, HashChainEngine hashChainEngine, AuditLogService auditLogService, ObjectMapper objectMapper) {
        this.repository = repository;
        this.hashChainEngine = hashChainEngine;
        this.auditLogService = auditLogService;
        this.objectMapper = objectMapper;
    }

    /**
     * Scenario C: Regulatory Client Account Access Compliance Audit Report.
     * Translates under-specified product mandate into a concrete, cryptographically-certified regulatory report.
     */
    @Transactional(readOnly = true)
    public ComplianceReport generateClientAccessReport(String clientAccountId, Instant from, Instant to) {
        if (clientAccountId == null || clientAccountId.trim().isEmpty()) {
            throw new IllegalArgumentException("clientAccountId is required for compliance audit reporting.");
        }

        Specification<AuditRecord> spec = (root, query, cb) -> {
            List<jakarta.persistence.criteria.Predicate> predicates = new ArrayList<>();
            predicates.add(cb.equal(root.get("resourceId"), clientAccountId));
            if (from != null) {
                predicates.add(cb.greaterThanOrEqualTo(root.get("timestamp"), from));
            }
            if (to != null) {
                predicates.add(cb.lessThanOrEqualTo(root.get("timestamp"), to));
            }
            return cb.and(predicates.toArray(new jakarta.persistence.criteria.Predicate[0]));
        };

        List<AuditRecord> records = repository.findAll(spec);
        records.sort(Comparator.comparing(AuditRecord::getTimestamp));

        // Group by actorId
        Map<String, List<AuditRecord>> byActor = records.stream()
                .collect(Collectors.groupingBy(AuditRecord::getActorId));

        List<ActorAccessSummary> summaries = new ArrayList<>();
        for (Map.Entry<String, List<AuditRecord>> entry : byActor.entrySet()) {
            String actorId = entry.getKey();
            List<AuditRecord> actorRecords = entry.getValue();

            Instant firstAccess = actorRecords.get(0).getTimestamp();
            Instant lastAccess = actorRecords.get(actorRecords.size() - 1).getTimestamp();
            List<String> eventTypes = actorRecords.stream()
                    .map(AuditRecord::getEventType)
                    .distinct()
                    .collect(Collectors.toList());

            summaries.add(ActorAccessSummary.builder()
                    .actorId(actorId)
                    .accessCount(actorRecords.size())
                    .firstAccess(firstAccess)
                    .lastAccess(lastAccess)
                    .eventTypes(eventTypes)
                    .build());
        }

        List<Map<String, Object>> trail = new ArrayList<>();
        for (AuditRecord r : records) {
            Map<String, Object> item = new HashMap<>();
            item.put("sequenceNumber", r.getSequenceNumber());
            item.put("eventType", r.getEventType());
            item.put("actorId", r.getActorId());
            item.put("resourceId", r.getResourceId());
            item.put("timestamp", r.getTimestamp().toString());
            try {
                item.put("payload", objectMapper.readValue(r.getPayloadJson(), new TypeReference<Map<String, Object>>() {}));
            } catch (Exception e) {
                item.put("payload", r.getPayloadJson());
            }
            item.put("recordHash", r.getRecordHash());
            trail.add(item);
        }

        VerificationResult verification = auditLogService.verifyChain();
        String reportId = "SEC-RPT-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();

        String proofInput = reportId + ":" + clientAccountId + ":" + records.size() + ":" + verification.isIntact();
        String proofToken = "PROOF-HMAC-SHA256:" + hashChainEngine.hmacSha256(proofInput, hmacSecret);

        return ComplianceReport.builder()
                .reportId(reportId)
                .title("Regulatory Compliance Audit Report: Client Account Access Trail")
                .generatedAt(Instant.now())
                .clientAccountId(clientAccountId)
                .fromTimestamp(from)
                .toTimestamp(to)
                .totalAccessEvents(records.size())
                .uniqueActors(byActor.size())
                .actorSummaries(summaries)
                .accessLogTrail(trail)
                .chainVerification(verification)
                .cryptographicProofToken(proofToken)
                .build();
    }
}

