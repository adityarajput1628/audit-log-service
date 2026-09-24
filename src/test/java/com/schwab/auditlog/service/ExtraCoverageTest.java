package com.schwab.auditlog.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.schwab.auditlog.crypto.HashChainEngine;
import com.schwab.auditlog.dto.*;
import com.schwab.auditlog.exception.*;
import com.schwab.auditlog.model.AuditRecord;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ExtraCoverageTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final HashChainEngine hashChainEngine = new HashChainEngine("unit_test_hmac_key_placeholder_32bytes");

    @Test
    @DisplayName("Test HashChainEngine edge cases and malformed JSON branches")
    void testHashChainEngineEdgeCases() {
        assertNotNull(hashChainEngine.sha256Hex("test_input"));
        assertNotNull(hashChainEngine.hmacSha256("test_input"));
        assertNotNull(hashChainEngine.hmacSha256("test_input", "custom_key"));
        assertNotNull(hashChainEngine.hashFieldValue("test_val", "salt_123"));
        assertNotNull(hashChainEngine.hashFieldValue(null, "salt_123"));

        // Payload hash with null/empty
        String emptyHash = hashChainEngine.calculatePayloadHash("", null, null);
        assertNotNull(emptyHash);

        // Malformed payload JSON throws IllegalArgumentException
        assertThrows(IllegalArgumentException.class, () ->
                hashChainEngine.calculatePayloadHash("{malformed_json:", null, null)
        );

        // Corrupt redactions JSON throws IllegalArgumentException
        assertThrows(IllegalArgumentException.class, () ->
                hashChainEngine.calculatePayloadHash("{\"key\":\"val\"}", "{corrupt_redactions:", null)
        );
    }

    @Test
    @DisplayName("Test DTOs getters, setters, equals, and builders")
    void testDtoCoverage() {
        CreateEventRequest req = CreateEventRequest.builder()
                .eventType("LOGIN")
                .actorId("actor1")
                .resourceType("AUTH")
                .resourceId("RES1")
                .timestamp(Instant.now())
                .payload(Map.of("k", "v"))
                .build();
        assertNotNull(req.getEventType());
        assertNotNull(req.getActorId());
        assertNotNull(req.getResourceType());
        assertNotNull(req.getResourceId());
        assertNotNull(req.getTimestamp());
        assertNotNull(req.getPayload());

        RedactFieldRequest redactReq = new RedactFieldRequest();
        redactReq.setFieldPath("ssn");
        redactReq.setReason("GDPR");
        assertEquals("ssn", redactReq.getFieldPath());
        assertEquals("GDPR", redactReq.getReason());

        RetentionRequest retReq = new RetentionRequest();
        retReq.setRetentionWindowDays(30);
        retReq.setDryRun(true);
        assertEquals(30, retReq.getRetentionWindowDays());
        assertTrue(retReq.isDryRun());

        VerificationResult.ViolationDetail violation = VerificationResult.ViolationDetail.builder()
                .sequenceNumber(1L)
                .recordId(10L)
                .violationType("HASH_MISMATCH")
                .expectedHash("exp")
                .actualHash("act")
                .description("desc")
                .build();
        assertEquals(1L, violation.getSequenceNumber());
        assertEquals(10L, violation.getRecordId());
        assertEquals("HASH_MISMATCH", violation.getViolationType());
        assertEquals("exp", violation.getExpectedHash());
        assertEquals("act", violation.getActualHash());
        assertEquals("desc", violation.getDescription());

        ExportBundle bundle = ExportBundle.builder()
                .exportId("EXP-1")
                .exportedAt(Instant.now())
                .filterType("actorId")
                .filterValue("alice")
                .recordCount(1)
                .records(List.of())
                .exportDigest("digest")
                .chainGenesisHash("gen")
                .chainLatestHash("latest")
                .verificationStatus("OK")
                .build();
        assertEquals("EXP-1", bundle.getExportId());

        ComplianceReport report = ComplianceReport.builder()
                .reportId("RPT-1")
                .title("Title")
                .generatedAt(Instant.now())
                .clientAccountId("ACC-1")
                .fromTimestamp(Instant.now())
                .toTimestamp(Instant.now())
                .totalAccessEvents(5)
                .uniqueActors(1)
                .actorSummaries(List.of())
                .accessLogTrail(List.of())
                .cryptographicProofToken("token")
                .build();
        assertEquals("RPT-1", report.getReportId());
    }

    @Test
    @DisplayName("Test Custom Exception Hierarchy")
    void testExceptionHierarchy() {
        AuditSerializationException ex1 = new AuditSerializationException("Serialization failed");
        assertEquals("Serialization failed", ex1.getMessage());

        AuditSerializationException ex2 = new AuditSerializationException("Failed", new RuntimeException());
        assertEquals("Failed", ex2.getMessage());

        AuditSecurityException ex3 = new AuditSecurityException("Security denied");
        assertEquals("Security denied", ex3.getMessage());
    }

    @Test
    @DisplayName("Test AuditRecord Model Getters/Setters")
    void testAuditRecordModel() {
        AuditRecord record = new AuditRecord();
        record.setId(100L);
        record.setSequenceNumber(1L);
        record.setEventType("TRADE");
        record.setActorId("bob");
        record.setResourceType("STOCK");
        record.setResourceId("AAPL");
        record.setPayloadJson("{}");
        record.setRedactionsJson("{}");
        record.setTimestamp(Instant.now());
        record.setPreviousHash("000");
        record.setRecordHash("111");
        record.setArchived(true);
        record.setArchivedAt(Instant.now());

        assertEquals(100L, record.getId());
        assertEquals(1L, record.getSequenceNumber());
        assertEquals("TRADE", record.getEventType());
        assertEquals("bob", record.getActorId());
        assertEquals("STOCK", record.getResourceType());
        assertEquals("AAPL", record.getResourceId());
        assertEquals("{}", record.getPayloadJson());
        assertEquals("{}", record.getRedactionsJson());
        assertNotNull(record.getTimestamp());
        assertEquals("000", record.getPreviousHash());
        assertEquals("111", record.getRecordHash());
        assertTrue(record.isArchived());
        assertNotNull(record.getArchivedAt());
    }
}
