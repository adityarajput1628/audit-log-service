package com.schwab.auditlog.service;

import com.schwab.auditlog.dto.CreateEventRequest;
import com.schwab.auditlog.dto.RetentionRequest;
import com.schwab.auditlog.dto.VerificationResult;
import com.schwab.auditlog.model.AuditRecord;
import com.schwab.auditlog.repository.AuditRecordRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
class ArchivedPayloadIntegrityTest {

    @Autowired
    private AuditLogService auditLogService;

    @Autowired
    private RetentionService retentionService;

    @Autowired
    private AuditRecordRepository repository;

    @BeforeEach
    void setUp() {
        repository.deleteAll();
    }

    @Test
    @DisplayName("Original archived payload verifies intact (PASS)")
    void testOriginalArchivedPayloadVerifyPasses() {
        Instant oldTime = Instant.now().minus(40, ChronoUnit.DAYS);
        auditLogService.createEvent(CreateEventRequest.builder()
                .eventType("TRANSFER")
                .actorId("user-1")
                .resourceType("ACCOUNT")
                .resourceId("ACC-1")
                .payload(Map.of("amount", 5000))
                .timestamp(oldTime)
                .build());

        retentionService.applyRetentionPolicy(new RetentionRequest(30, false));

        VerificationResult result = auditLogService.verifyChain();
        assertThat(result.isIntact()).isTrue();
        assertThat(result.getArchivedRecordsChecked()).isEqualTo(1);
    }

    @Test
    @DisplayName("Mutate archived payload ONLY must cause verification to FAIL")
    void testMutateArchivedPayloadFails() {
        Instant oldTime = Instant.now().minus(40, ChronoUnit.DAYS);
        AuditRecord record = auditLogService.createEvent(CreateEventRequest.builder()
                .eventType("TRANSFER")
                .actorId("user-1")
                .resourceType("ACCOUNT")
                .resourceId("ACC-1")
                .payload(Map.of("amount", 5000))
                .timestamp(oldTime)
                .build());

        retentionService.applyRetentionPolicy(new RetentionRequest(30, false));

        AuditRecord archived = repository.findById(record.getId()).orElseThrow();
        // Mutate payloadJson directly in DB without changing stored recordHash
        archived.setPayloadJson("{\"_archived\":true,\"_archivedAt\":\"" + archived.getArchivedAt() + "\",\"_retentionWindowDays\":30,\"malicious\":\"extra_data\"}");
        repository.save(archived);

        VerificationResult result = auditLogService.verifyChain();
        assertThat(result.isIntact()).isFalse();
        assertThat(result.getViolations()).hasSize(1);
        assertThat(result.getViolations().get(0).getViolationType()).isEqualTo("HASH_MISMATCH");
    }

    @Test
    @DisplayName("Mutate actorId ONLY on archived record must cause verification to FAIL")
    void testMutateActorIdFails() {
        Instant oldTime = Instant.now().minus(40, ChronoUnit.DAYS);
        AuditRecord record = auditLogService.createEvent(CreateEventRequest.builder()
                .eventType("TRANSFER")
                .actorId("user-1")
                .resourceType("ACCOUNT")
                .resourceId("ACC-1")
                .payload(Map.of("amount", 5000))
                .timestamp(oldTime)
                .build());

        retentionService.applyRetentionPolicy(new RetentionRequest(30, false));

        AuditRecord archived = repository.findById(record.getId()).orElseThrow();
        archived.setActorId("hacker_actor");
        repository.save(archived);

        VerificationResult result = auditLogService.verifyChain();
        assertThat(result.isIntact()).isFalse();
        assertThat(result.getViolations().get(0).getViolationType()).isEqualTo("HASH_MISMATCH");
    }

    @Test
    @DisplayName("Mutate timestamp ONLY on archived record must cause verification to FAIL")
    void testMutateTimestampFails() {
        Instant oldTime = Instant.now().minus(40, ChronoUnit.DAYS);
        AuditRecord record = auditLogService.createEvent(CreateEventRequest.builder()
                .eventType("TRANSFER")
                .actorId("user-1")
                .resourceType("ACCOUNT")
                .resourceId("ACC-1")
                .payload(Map.of("amount", 5000))
                .timestamp(oldTime)
                .build());

        retentionService.applyRetentionPolicy(new RetentionRequest(30, false));

        AuditRecord archived = repository.findById(record.getId()).orElseThrow();
        archived.setTimestamp(Instant.now());
        repository.save(archived);

        VerificationResult result = auditLogService.verifyChain();
        assertThat(result.isIntact()).isFalse();
        assertThat(result.getViolations().get(0).getViolationType()).isEqualTo("HASH_MISMATCH");
    }

    @Test
    @DisplayName("Mutate stored hash ONLY on archived record must cause verification to FAIL")
    void testMutateStoredHashFails() {
        Instant oldTime = Instant.now().minus(40, ChronoUnit.DAYS);
        AuditRecord record = auditLogService.createEvent(CreateEventRequest.builder()
                .eventType("TRANSFER")
                .actorId("user-1")
                .resourceType("ACCOUNT")
                .resourceId("ACC-1")
                .payload(Map.of("amount", 5000))
                .timestamp(oldTime)
                .build());

        retentionService.applyRetentionPolicy(new RetentionRequest(30, false));

        AuditRecord archived = repository.findById(record.getId()).orElseThrow();
        archived.setRecordHash("000000000000000000000000000000000000000000000000000000000000ffff");
        repository.save(archived);

        VerificationResult result = auditLogService.verifyChain();
        assertThat(result.isIntact()).isFalse();
        assertThat(result.getViolations().get(0).getViolationType()).isEqualTo("HASH_MISMATCH");
    }

    @Test
    @DisplayName("JSON formatting changes follow canonicalization rules and verify PASS")
    void testJsonFormattingFollowsCanonicalizationRules() {
        Instant oldTime = Instant.now().minus(40, ChronoUnit.DAYS);
        AuditRecord record = auditLogService.createEvent(CreateEventRequest.builder()
                .eventType("TRANSFER")
                .actorId("user-1")
                .resourceType("ACCOUNT")
                .resourceId("ACC-1")
                .payload(Map.of("amount", 5000))
                .timestamp(oldTime)
                .build());

        retentionService.applyRetentionPolicy(new RetentionRequest(30, false));

        AuditRecord archived = repository.findById(record.getId()).orElseThrow();
        // Equivalent JSON content with different whitespace and key formatting order
        String reformatted = "{\n  \"_retentionWindowDays\": 30,\n  \"_archivedAt\": \"" + archived.getArchivedAt() + "\",\n  \"_archived\": true\n}";
        archived.setPayloadJson(reformatted);
        repository.save(archived);

        VerificationResult result = auditLogService.verifyChain();
        assertThat(result.isIntact()).isTrue();
    }
}
