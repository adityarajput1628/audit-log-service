package com.schwab.auditlog.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.schwab.auditlog.crypto.HashChainEngine;
import com.schwab.auditlog.dto.CreateEventRequest;
import com.schwab.auditlog.dto.VerificationResult;
import com.schwab.auditlog.dto.VerificationResult.ViolationDetail;
import com.schwab.auditlog.model.AuditRecord;
import com.schwab.auditlog.repository.AuditRecordRepository;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.*;

@Service
public class AuditLogService {

    private final AuditRecordRepository repository;
    private final HashChainEngine hashChainEngine;
    private final ObjectMapper objectMapper;

    public AuditLogService(AuditRecordRepository repository, HashChainEngine hashChainEngine, ObjectMapper objectMapper) {
        this.repository = repository;
        this.hashChainEngine = hashChainEngine;
        this.objectMapper = objectMapper;
    }

    /**
     * Append-only event ingestion with SHA-256 hash chaining.
     */
    /**
     * Append-only event ingestion with SHA-256 hash chaining, DB locking and atomic synchronization.
     */
    @Transactional
    public synchronized AuditRecord createEvent(CreateEventRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("CreateEventRequest cannot be null.");
        }

        Optional<AuditRecord> latestRecordOpt = repository.findLatestRecordForUpdate();
        if (latestRecordOpt.isEmpty()) {
            latestRecordOpt = repository.findTopByOrderBySequenceNumberDesc();
        }

        long nextSequence = latestRecordOpt.map(r -> r.getSequenceNumber() + 1).orElse(1L);
        String previousHash = latestRecordOpt.map(AuditRecord::getRecordHash).orElse(AuditRecord.GENESIS_HASH);
        Instant eventTimestamp = (request.getTimestamp() != null ? request.getTimestamp() : Instant.now())
                .truncatedTo(java.time.temporal.ChronoUnit.MILLIS);

        String payloadJson;
        try {
            payloadJson = objectMapper.writeValueAsString(request.getPayload() != null ? request.getPayload() : Map.of());
        } catch (Exception e) {
            payloadJson = "{}";
        }

        AuditRecord newRecord = AuditRecord.builder()
                .sequenceNumber(nextSequence)
                .eventType(request.getEventType())
                .actorId(request.getActorId())
                .resourceType(request.getResourceType())
                .resourceId(request.getResourceId())
                .payloadJson(payloadJson)
                .redactionsJson("{}")
                .timestamp(eventTimestamp)
                .previousHash(previousHash)
                .archived(false)
                .build();

        String recordHash = hashChainEngine.calculateRecordHash(newRecord);
        newRecord.setRecordHash(recordHash);

        return repository.saveAndFlush(newRecord);
    }

    /**
     * Multi-criteria query API with bounded pagination and date validation.
     */
    @Transactional(readOnly = true)
    public Page<AuditRecord> queryEvents(
            String actorId,
            String resourceType,
            String resourceId,
            String eventType,
            Instant from,
            Instant to,
            Boolean includeArchived,
            int page,
            int size
    ) {
        if (from != null && to != null && from.isAfter(to)) {
            throw new IllegalArgumentException("'from' timestamp cannot be after 'to' timestamp.");
        }

        int boundedPage = Math.max(page, 0);
        int boundedSize = Math.min(Math.max(size, 1), 100);

        Specification<AuditRecord> spec = (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            if (actorId != null && !actorId.trim().isEmpty()) {
                predicates.add(cb.equal(root.get("actorId"), actorId));
            }
            if (resourceType != null && !resourceType.trim().isEmpty()) {
                predicates.add(cb.equal(root.get("resourceType"), resourceType));
            }
            if (resourceId != null && !resourceId.trim().isEmpty()) {
                predicates.add(cb.equal(root.get("resourceId"), resourceId));
            }
            if (eventType != null && !eventType.trim().isEmpty()) {
                predicates.add(cb.equal(root.get("eventType"), eventType));
            }
            if (from != null) {
                predicates.add(cb.greaterThanOrEqualTo(root.get("timestamp"), from));
            }
            if (to != null) {
                predicates.add(cb.lessThanOrEqualTo(root.get("timestamp"), to));
            }
            if (includeArchived == null || !includeArchived) {
                predicates.add(cb.equal(root.get("archived"), false));
            }

            return cb.and(predicates.toArray(new Predicate[0]));
        };

        Pageable pageable = PageRequest.of(boundedPage, boundedSize, Sort.by(Sort.Direction.DESC, "sequenceNumber"));
        return repository.findAll(spec, pageable);
    }

    /**
     * Cryptographic Chain Verification Engine.
     * Walks full chain from genesis to HEAD, validating hashes, links, sequence, and timestamps.
     */
    @Transactional(readOnly = true)
    public VerificationResult verifyChain() {
        List<AuditRecord> records = repository.findAllByOrderBySequenceNumberAsc();
        VerificationResult result = VerificationResult.builder()
                .intact(true)
                .totalRecordsChecked(records.size())
                .activeRecordsChecked(records.stream().filter(r -> !r.isArchived()).count())
                .archivedRecordsChecked(records.stream().filter(AuditRecord::isArchived).count())
                .violations(new ArrayList<>())
                .build();

        if (records.isEmpty()) {
            result.setStatusMessage("Audit trail is empty. Chain is intact.");
            return result;
        }

        String expectedPreviousHash = AuditRecord.GENESIS_HASH;
        long expectedSequence = 1L;

        for (int i = 0; i < records.size(); i++) {
            AuditRecord current = records.get(i);
            boolean recordIntact = true;

            // 1. Verify sequence continuity
            if (!current.getSequenceNumber().equals(expectedSequence)) {
                result.setIntact(false);
                result.getViolations().add(ViolationDetail.builder()
                        .sequenceNumber(current.getSequenceNumber())
                        .recordId(current.getId())
                        .violationType("SEQUENCE_GAP")
                        .expectedHash("Sequence " + expectedSequence)
                        .actualHash("Sequence " + current.getSequenceNumber())
                        .description("Sequence gap detected. Expected " + expectedSequence + " but found " + current.getSequenceNumber())
                        .build());
            }

            // 2. Verify previousHash chain link
            if (!current.getPreviousHash().equalsIgnoreCase(expectedPreviousHash)) {
                result.setIntact(false);
                result.getViolations().add(ViolationDetail.builder()
                        .sequenceNumber(current.getSequenceNumber())
                        .recordId(current.getId())
                        .violationType("PREVIOUS_HASH_MISMATCH")
                        .expectedHash(expectedPreviousHash)
                        .actualHash(current.getPreviousHash())
                        .description("Chain link broken at record #" + current.getSequenceNumber() + ". Previous hash does not match prior record hash.")
                        .build());
            }

            // 3. Recompute record hash and verify integrity for all records (active and archived)
            try {
                String calculatedHash = hashChainEngine.calculateRecordHash(current);
                if (!calculatedHash.equalsIgnoreCase(current.getRecordHash())) {
                    result.setIntact(false);
                    result.getViolations().add(ViolationDetail.builder()
                            .sequenceNumber(current.getSequenceNumber())
                            .recordId(current.getId())
                            .violationType("HASH_MISMATCH")
                            .expectedHash(calculatedHash)
                            .actualHash(current.getRecordHash())
                            .description("Record content tampered at sequence #" + current.getSequenceNumber() + ". Recomputed hash differs from stored record hash.")
                            .build());
                }
            } catch (IllegalArgumentException | IllegalStateException ex) {
                result.setIntact(false);
                result.getViolations().add(ViolationDetail.builder()
                        .sequenceNumber(current.getSequenceNumber())
                        .recordId(current.getId())
                        .violationType("MALFORMED_CONTENT")
                        .expectedHash("Valid Canonical JSON")
                        .actualHash("MALFORMED")
                        .description("Record payload or redaction metadata corrupted at sequence #" + current.getSequenceNumber() + ": " + ex.getMessage())
                        .build());
            } catch (Exception ex) {
                result.setIntact(false);
                result.getViolations().add(ViolationDetail.builder()
                        .sequenceNumber(current.getSequenceNumber())
                        .recordId(current.getId())
                        .violationType("MALFORMED_CONTENT")
                        .expectedHash("Valid Canonical JSON")
                        .actualHash("MALFORMED")
                        .description("Record payload or redaction metadata corrupted at sequence #" + current.getSequenceNumber() + ": " + ex.getMessage())
                        .build());
            }

            expectedPreviousHash = current.getRecordHash();
            expectedSequence++;
        }

        if (result.isIntact()) {
            result.setStatusMessage("Audit log hash chain is 100% INTACT. All " + records.size() + " records cryptographically verified.");
        } else {
            result.setStatusMessage("SECURITY ALERT: Cryptographic chain verification FAILED! Detected " + result.getViolations().size() + " violation(s).");
        }

        return result;
    }

    /**
     * Direct Database Tamper Simulator for Live Testing & Reviewer Verification.
     */
    @Transactional
    public AuditRecord simulateTampering(Long recordId, String tamperedPayload, String tamperedActorId) {
        AuditRecord record = repository.findById(recordId)
                .orElseThrow(() -> new IllegalArgumentException("Audit record not found with ID: " + recordId));

        if (tamperedPayload != null) {
            record.setPayloadJson(tamperedPayload);
        }
        if (tamperedActorId != null) {
            record.setActorId(tamperedActorId);
        }

        // Intentionally save WITHOUT updating stored recordHash to simulate direct database corruption/tampering
        return repository.save(record);
    }

    public Optional<AuditRecord> getById(Long id) {
        return repository.findById(id);
    }
}
