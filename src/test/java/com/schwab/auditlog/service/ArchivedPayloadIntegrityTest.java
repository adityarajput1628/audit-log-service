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
    @DisplayName("1. Original archived payload verifies intact (PASS)")
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
    @DisplayName("2. Mutate archived payload ONLY must cause verification to FAIL")
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
        // Mutate payloadJson ONLY directly in DB without changing stored recordHash, actorId, timestamp, previousHash or redactionsJson
        archived.setPayloadJson("{\"_archived\":true,\"_archivedAt\":\"" + archived.getArchivedAt() + "\",\"_retentionWindowDays\":30,\"malicious\":\"unauthorized_mutation\"}");
        repository.save(archived);

        VerificationResult result = auditLogService.verifyChain();
        assertThat(result.isIntact()).isFalse();
        assertThat(result.getViolations()).hasSize(1);
        assertThat(result.getViolations().get(0).getViolationType()).isEqualTo("HASH_MISMATCH");
    }

    @Test
    @DisplayName("3. Add additional field to archived payload must cause verification to FAIL")
    void testArchivedPayloadAdditionalFieldFails() {
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
        archived.setPayloadJson("{\"_archived\":true,\"_archivedAt\":\"" + archived.getArchivedAt() + "\",\"_extraField\":\"injected\",\"_retentionWindowDays\":30}");
        repository.save(archived);

        VerificationResult result = auditLogService.verifyChain();
        assertThat(result.isIntact()).isFalse();
        assertThat(result.getViolations().get(0).getViolationType()).isEqualTo("HASH_MISMATCH");
    }

    @Test
    @DisplayName("4. Modify value of tombstone field must cause verification to FAIL")
    void testArchivedPayloadValueModificationFails() {
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
        archived.setPayloadJson("{\"_archived\":false,\"_archivedAt\":\"" + archived.getArchivedAt() + "\",\"_retentionWindowDays\":30}");
        repository.save(archived);

        VerificationResult result = auditLogService.verifyChain();
        assertThat(result.isIntact()).isFalse();
        assertThat(result.getViolations().get(0).getViolationType()).isEqualTo("HASH_MISMATCH");
    }

    @Test
    @DisplayName("5. Mutate actorId ONLY on archived record must cause verification to FAIL")
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
    @DisplayName("6. Mutate timestamp ONLY on archived record must cause verification to FAIL")
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
    @DisplayName("7. Mutate previousHash ONLY on archived record must cause verification to FAIL")
    void testMutatePreviousHashFails() {
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
        archived.setPreviousHash("000000000000000000000000000000000000000000000000000000000000bad1");
        repository.save(archived);

        VerificationResult result = auditLogService.verifyChain();
        assertThat(result.isIntact()).isFalse();
        assertThat(result.getViolations().get(0).getViolationType()).isEqualTo("PREVIOUS_HASH_MISMATCH");
    }

    @Test
    @DisplayName("8. Mutate stored recordHash ONLY on archived record must cause verification to FAIL")
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
    @DisplayName("9. JSON formatting changes follow canonicalization rules and verify PASS")
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

    @Test
    @DisplayName("10. Malformed archived payload causes verification to FAIL with MALFORMED_CONTENT")
    void testMalformedArchivedPayloadFails() {
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
        archived.setPayloadJson("{malformed_json_content...");
        repository.save(archived);

        VerificationResult result = auditLogService.verifyChain();
        assertThat(result.isIntact()).isFalse();
        assertThat(result.getViolations().get(0).getViolationType()).isEqualTo("MALFORMED_CONTENT");
    }

    @Test
    @DisplayName("11. Corrupt redactions metadata JSON causes verification to FAIL with MALFORMED_CONTENT")
    void testCorruptIntegrityMetadataFails() {
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
        archived.setRedactionsJson("{corrupt_metadata_json...");
        repository.save(archived);

        VerificationResult result = auditLogService.verifyChain();
        assertThat(result.isIntact()).isFalse();
        assertThat(result.getViolations().get(0).getViolationType()).isEqualTo("MALFORMED_CONTENT");
    }
}
