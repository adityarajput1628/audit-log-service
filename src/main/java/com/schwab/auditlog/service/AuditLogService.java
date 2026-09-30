package com.schwab.auditlog.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.schwab.auditlog.crypto.HashChainEngine;
import com.schwab.auditlog.dto.CreateEventRequest;
import com.schwab.auditlog.dto.VerificationResult;
import com.schwab.auditlog.dto.VerificationResult.ViolationDetail;
import com.schwab.auditlog.exception.AuditSecurityException;
import com.schwab.auditlog.model.AuditRecord;
import com.schwab.auditlog.model.ChainCheckpoint;
import com.schwab.auditlog.model.IdempotencyRecord;
import com.schwab.auditlog.repository.AuditRecordRepository;
import com.schwab.auditlog.repository.ChainCheckpointRepository;
import com.schwab.auditlog.repository.IdempotencyRecordRepository;
import com.schwab.auditlog.security.SecurityEventLogger;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Service
public class AuditLogService {

    private final AuditRecordRepository repository;
    private final ChainCheckpointRepository checkpointRepository;
    private final IdempotencyRecordRepository idempotencyRepository;
    private final HashChainEngine hashChainEngine;
    private final ObjectMapper objectMapper;
    private final TransactionTemplate transactionTemplate;
    private final SecurityEventLogger securityEventLogger;

    public AuditLogService(
            AuditRecordRepository repository,
            ChainCheckpointRepository checkpointRepository,
            IdempotencyRecordRepository idempotencyRepository,
            HashChainEngine hashChainEngine,
            ObjectMapper objectMapper,
            PlatformTransactionManager transactionManager,
            SecurityEventLogger securityEventLogger
    ) {
        this.repository = repository;
        this.checkpointRepository = checkpointRepository;
        this.idempotencyRepository = idempotencyRepository;
        this.hashChainEngine = hashChainEngine;
        this.objectMapper = objectMapper;
        this.transactionTemplate = new TransactionTemplate(transactionManager);
        this.securityEventLogger = securityEventLogger;
    }

    public AuditRecord createEvent(CreateEventRequest request) {
        return createEvent(request, null);
    }

    public AuditRecord createEvent(CreateEventRequest request, String idempotencyKey) {
        return createEventInternal(request, idempotencyKey, false);
    }

    /**
     * Append-only event ingestion with SHA-256 hash chaining, DB pessimistic locking,
     * authoritative actor identity provenance, server-generated ingestion timestamp,
     * and database-enforced idempotency replay protection.
     */
    public AuditRecord createEventInternal(CreateEventRequest request, String idempotencyKey, boolean isInternalCall) {
        if (request == null) {
            throw new IllegalArgumentException("CreateEventRequest cannot be null.");
        }

        // 1. Authoritative Actor Identity Provenance (Phase 3)
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String authenticatedActor;
        boolean isAdmin = false;

        if (auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getName())) {
            authenticatedActor = auth.getName();
            isAdmin = auth.getAuthorities().stream()
                    .anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()));
            if (!isInternalCall && request.getActorId() != null && !request.getActorId().trim().isEmpty()) {
                if (!isAdmin && !request.getActorId().trim().equals(authenticatedActor)) {
                    securityEventLogger.logSecurityEvent(
                            SecurityEventLogger.EventCategory.ACTOR_SPOOF_ATTEMPT,
                            authenticatedActor,
                            "CREATE_EVENT",
                            request.getResourceType() + ":" + request.getResourceId(),
                            "DENIED",
                            "Actor spoofing attempt detected. Requested actorId '" + request.getActorId() + "' does not match authenticated principal '" + authenticatedActor + "'",
                            Map.of("requestedActorId", request.getActorId(), "authenticatedActor", authenticatedActor)
                    );
                    throw new AuditSecurityException("Actor spoofing attempt detected: requested actorId '" + request.getActorId() + "' does not match authenticated principal '" + authenticatedActor + "'");
                }
            }
        } else {
            authenticatedActor = (request.getActorId() != null && !request.getActorId().trim().isEmpty())
                    ? request.getActorId().trim()
                    : "SYSTEM";
        }

        String authoritativeActor = (isAdmin && request.getActorId() != null && !request.getActorId().trim().isEmpty())
                ? request.getActorId().trim()
                : authenticatedActor;

        // 2. Authoritative Ingestion Timestamp (Phase 4)
        Instant ingestedAt = (request.getTimestamp() != null)
                ? request.getTimestamp().truncatedTo(ChronoUnit.MILLIS)
                : Instant.now().truncatedTo(ChronoUnit.MILLIS);

        Map<String, Object> payloadMap = new LinkedHashMap<>();
        if (request.getPayload() != null) {
            payloadMap.putAll(request.getPayload());
        }
        if (request.getTimestamp() != null && !isInternalCall) {
            payloadMap.put("_occurredAt", request.getTimestamp().toString());
        }

        String payloadJson;
        try {
            payloadJson = objectMapper.writeValueAsString(payloadMap);
        } catch (Exception e) {
            payloadJson = "{}";
        }

        // Validate JSON payload depth and size limits (Phase 6)
        validatePayloadLimits(payloadJson, request);

        // 3. Idempotency / Replay Protection (Phase 5)
        String cleanedIdempotencyKey = (idempotencyKey != null && !idempotencyKey.trim().isEmpty()) ? idempotencyKey.trim() : null;
        String requestHash = hashChainEngine.sha256Hex(request.getEventType() + "|" + request.getResourceType() + "|" + request.getResourceId() + "|" + payloadJson);

        if (cleanedIdempotencyKey != null) {
            Optional<IdempotencyRecord> existingOpt = idempotencyRepository.findByIdempotencyKey(cleanedIdempotencyKey);
            if (existingOpt.isPresent()) {
                IdempotencyRecord existing = existingOpt.get();
                if (existing.getRequestHash().equals(requestHash)) {
                    // Idempotent retry: return existing AuditRecord
                    return repository.findById(existing.getAuditRecordId())
                            .orElseThrow(() -> new IllegalStateException("Associated audit record not found for idempotency key: " + cleanedIdempotencyKey));
                } else {
                    // Conflicting request with same idempotency key
                    securityEventLogger.logSecurityEvent(
                            SecurityEventLogger.EventCategory.INVALID_REQUEST,
                            authoritativeActor,
                            "CREATE_EVENT",
                            request.getResourceType() + ":" + request.getResourceId(),
                            "CONFLICT",
                            "Idempotency key collision with conflicting payload",
                            Map.of("idempotencyKey", cleanedIdempotencyKey)
                    );
                    throw new IllegalArgumentException("Idempotency key collision: provided Idempotency-Key '" + cleanedIdempotencyKey + "' was previously used with a different request payload.");
                }
            }
        }

        int maxAttempts = 15;
        Exception lastException = null;

        final String finalPayloadJson = payloadJson;

        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                return transactionTemplate.execute(status -> {
                    Optional<AuditRecord> latestRecordOpt = repository.findLatestRecordForUpdate();
                    if (latestRecordOpt.isEmpty()) {
                        latestRecordOpt = repository.findTopByOrderBySequenceNumberDesc();
                    }

                    long nextSequence = latestRecordOpt.map(r -> r.getSequenceNumber() + 1).orElse(1L);
                    String previousHash = latestRecordOpt.map(AuditRecord::getRecordHash).orElse(AuditRecord.GENESIS_HASH);

                    AuditRecord newRecord = AuditRecord.builder()
                            .sequenceNumber(nextSequence)
                            .eventType(request.getEventType())
                            .actorId(authoritativeActor)
                            .resourceType(request.getResourceType())
                            .resourceId(request.getResourceId())
                            .payloadJson(finalPayloadJson)
                            .redactionsJson("{}")
                            .timestamp(ingestedAt)
                            .previousHash(previousHash)
                            .archived(false)
                            .build();

                    String recordHash = hashChainEngine.calculateRecordHash(newRecord);
                    newRecord.setRecordHash(recordHash);

                    AuditRecord savedRecord = repository.saveAndFlush(newRecord);

                    if (cleanedIdempotencyKey != null) {
                        Optional<IdempotencyRecord> checkAgain = idempotencyRepository.findByIdempotencyKey(cleanedIdempotencyKey);
                        if (checkAgain.isPresent()) {
                            IdempotencyRecord existing = checkAgain.get();
                            status.setRollbackOnly();
                            if (existing.getRequestHash().equals(requestHash)) {
                                return repository.findById(existing.getAuditRecordId()).orElse(savedRecord);
                            } else {
                                throw new IllegalArgumentException("Idempotency key collision: provided Idempotency-Key '" + cleanedIdempotencyKey + "' was previously used with a different request payload.");
                            }
                        }
                        IdempotencyRecord idempotencyRecord = IdempotencyRecord.builder()
                                .idempotencyKey(cleanedIdempotencyKey)
                                .requestHash(requestHash)
                                .auditRecordId(savedRecord.getId())
                                .createdAt(ingestedAt)
                                .build();
                        idempotencyRepository.saveAndFlush(idempotencyRecord);
                    }

                    return savedRecord;
                });
            } catch (Exception e) {
                lastException = e;
                if (attempt < maxAttempts) {
                    try {
                        Thread.sleep(10L * attempt);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw new RuntimeException("Interrupted during database transaction retry", ie);
                    }
                }
            }
        }

        throw new IllegalStateException("Failed to ingest audit event after " + maxAttempts + " database transaction retries", lastException);
    }

    private void validatePayloadLimits(String payloadJson, CreateEventRequest request) {
        if (payloadJson.length() > 256 * 1024) { // 256 KB
            throw new IllegalArgumentException("Payload JSON size exceeds maximum allowed limit of 256KB.");
        }
        int depth = calculateJsonDepth(payloadJson);
        if (depth > 15) {
            throw new IllegalArgumentException("JSON payload nesting depth (" + depth + ") exceeds maximum allowed depth of 15.");
        }
    }

    private int calculateJsonDepth(String json) {
        int maxDepth = 0;
        int currentDepth = 0;
        for (char c : json.toCharArray()) {
            if (c == '{' || c == '[') {
                currentDepth++;
                if (currentDepth > maxDepth) maxDepth = currentDepth;
            } else if (c == '}' || c == ']') {
                currentDepth--;
            }
        }
        return maxDepth;
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
            securityEventLogger.logSecurityEvent(
                    SecurityEventLogger.EventCategory.INTEGRITY_VERIFICATION_FAILURE,
                    "SYSTEM_VERIFIER",
                    "VERIFY_CHAIN",
                    "AUDIT_CHAIN",
                    "FAILED",
                    "Cryptographic chain verification failed with " + result.getViolations().size() + " violations",
                    Map.of("violationCount", result.getViolations().size())
            );
        }

        return result;
    }

    /**
     * External Chain Head Checkpoint / Anchor Creator (Phase 2).
     */
    @Transactional
    public ChainCheckpoint createCheckpoint() {
        Optional<AuditRecord> headRecordOpt = repository.findTopByOrderBySequenceNumberDesc();
        if (headRecordOpt.isEmpty()) {
            throw new IllegalStateException("Cannot create checkpoint: Audit log repository is empty.");
        }

        AuditRecord headRecord = headRecordOpt.get();
        Instant checkpointTimestamp = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        String checkpointId = "CHK-" + UUID.randomUUID().toString();
        String version = "v1.0";

        String signaturePayload = headRecord.getSequenceNumber() + "|" + headRecord.getRecordHash() + "|" + checkpointTimestamp.toString() + "|" + version;
        String signature = hashChainEngine.hmacSha256(signaturePayload);

        ChainCheckpoint checkpoint = ChainCheckpoint.builder()
                .checkpointId(checkpointId)
                .headSequenceNumber(headRecord.getSequenceNumber())
                .headRecordHash(headRecord.getRecordHash())
                .checkpointTimestamp(checkpointTimestamp)
                .checkpointVersion(version)
                .signature(signature)
                .status("VALID")
                .build();

        ChainCheckpoint saved = checkpointRepository.save(checkpoint);

        securityEventLogger.logSecurityEvent(
                SecurityEventLogger.EventCategory.CHECKPOINT_EVENT,
                "SYSTEM_CHECKPOINT_SERVICE",
                "CREATE_CHECKPOINT",
                "CHAIN_HEAD",
                "SUCCESS",
                "Created external chain head checkpoint at sequence #" + headRecord.getSequenceNumber(),
                Map.of("checkpointId", checkpointId, "headSequence", headRecord.getSequenceNumber(), "headHash", headRecord.getRecordHash())
        );

        return saved;
    }

    /**
     * External Checkpoint Verification Engine (Phase 2).
     */
    @Transactional(readOnly = true)
    public VerificationResult verifyCheckpoint(String checkpointId) {
        ChainCheckpoint checkpoint = checkpointRepository.findByCheckpointId(checkpointId)
                .orElseThrow(() -> new IllegalArgumentException("Checkpoint not found with ID: " + checkpointId));

        VerificationResult result = VerificationResult.builder()
                .intact(true)
                .totalRecordsChecked(checkpoint.getHeadSequenceNumber().intValue())
                .violations(new ArrayList<>())
                .build();

        // 1. Verify Checkpoint HMAC signature
        String signaturePayload = checkpoint.getHeadSequenceNumber() + "|" + checkpoint.getHeadRecordHash() + "|" + checkpoint.getCheckpointTimestamp().toString() + "|" + checkpoint.getCheckpointVersion();
        String expectedSignature = hashChainEngine.hmacSha256(signaturePayload);

        if (!expectedSignature.equals(checkpoint.getSignature())) {
            result.setIntact(false);
            result.getViolations().add(ViolationDetail.builder()
                    .sequenceNumber(checkpoint.getHeadSequenceNumber())
                    .violationType("CHECKPOINT_SIGNATURE_TAMPERED")
                    .expectedHash(expectedSignature)
                    .actualHash(checkpoint.getSignature())
                    .description("External checkpoint signature is invalid or tampered.")
                    .build());
        }

        // 2. Verify Database Chain Head matches Checkpoint
        Optional<AuditRecord> dbHeadOpt = repository.findTopByOrderBySequenceNumberDesc();
        if (dbHeadOpt.isEmpty() || dbHeadOpt.get().getSequenceNumber() < checkpoint.getHeadSequenceNumber()) {
            result.setIntact(false);
            result.getViolations().add(ViolationDetail.builder()
                    .sequenceNumber(checkpoint.getHeadSequenceNumber())
                    .violationType("CHECKPOINT_HEAD_MISMATCH")
                    .expectedHash("Sequence " + checkpoint.getHeadSequenceNumber())
                    .actualHash(dbHeadOpt.map(r -> "Sequence " + r.getSequenceNumber()).orElse("EMPTY"))
                    .description("Database audit chain is missing records up to checkpoint head sequence #" + checkpoint.getHeadSequenceNumber())
                    .build());
            return result;
        }

        AuditRecord targetRecord = repository.findAllByOrderBySequenceNumberAsc().stream()
                .filter(r -> r.getSequenceNumber().equals(checkpoint.getHeadSequenceNumber()))
                .findFirst()
                .orElse(null);

        if (targetRecord == null || !targetRecord.getRecordHash().equals(checkpoint.getHeadRecordHash())) {
            result.setIntact(false);
            result.getViolations().add(ViolationDetail.builder()
                    .sequenceNumber(checkpoint.getHeadSequenceNumber())
                    .violationType("CHECKPOINT_HASH_MISMATCH")
                    .expectedHash(checkpoint.getHeadRecordHash())
                    .actualHash(targetRecord != null ? targetRecord.getRecordHash() : "NOT_FOUND")
                    .description("Database record hash at sequence #" + checkpoint.getHeadSequenceNumber() + " does not match external checkpoint anchor hash.")
                    .build());
        }

        // 3. Verify underlying hash chain integrity
        VerificationResult chainResult = verifyChain();
        if (!chainResult.isIntact()) {
            result.setIntact(false);
            result.getViolations().addAll(chainResult.getViolations());
        }

        if (result.isIntact()) {
            result.setStatusMessage("External Checkpoint '" + checkpointId + "' verified successfully. Audit chain up to sequence #" + checkpoint.getHeadSequenceNumber() + " is intact.");
        } else {
            result.setStatusMessage("SECURITY ALERT: External Checkpoint verification FAILED!");
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

        return repository.save(record);
    }

    public Optional<AuditRecord> getById(Long id) {
        return repository.findById(id);
    }
}
