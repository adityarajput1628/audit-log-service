package com.schwab.auditlog.service;

import com.schwab.auditlog.dto.CreateEventRequest;
import com.schwab.auditlog.dto.VerificationResult;
import com.schwab.auditlog.model.AuditRecord;
import com.schwab.auditlog.repository.AuditRecordRepository;
import com.schwab.auditlog.repository.IdempotencyRecordRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
public class FailureAndRollbackTest {

    @Autowired
    private AuditLogService auditLogService;

    @Autowired
    private AuditRecordRepository auditRecordRepository;

    @Autowired
    private IdempotencyRecordRepository idempotencyRecordRepository;

    @Test
    @WithMockUser(username = "ingest_user", roles = {"INGEST"})
    @DisplayName("Phase 13: Failed transaction leaves no orphaned records, gaps, or broken chain state")
    void testFailedTransactionRollbackSafety() {
        CreateEventRequest validReq = CreateEventRequest.builder()
                .eventType("INITIAL_EVENT")
                .actorId("ingest_user")
                .resourceType("RESOURCE")
                .resourceId("RES-1")
                .payload(Map.of("val", 100))
                .build();
        AuditRecord rec1 = auditLogService.createEvent(validReq);
        long initialCount = auditRecordRepository.count();

        // Attempt invalid creation with oversized payload to force a failure
        String oversized = "X".repeat(300 * 1024);
        CreateEventRequest invalidReq = CreateEventRequest.builder()
                .eventType("FAILED_EVENT")
                .actorId("ingest_user")
                .resourceType("RESOURCE")
                .resourceId("RES-2")
                .payload(Map.of("data", oversized))
                .build();

        assertThrows(IllegalArgumentException.class, () -> auditLogService.createEvent(invalidReq, "FAILED-KEY-1"));

        // Verify count remains unchanged and idempotency key was not saved
        assertEquals(initialCount, auditRecordRepository.count());
        assertTrue(idempotencyRecordRepository.findByIdempotencyKey("FAILED-KEY-1").isEmpty());

        // Create a subsequent valid event
        CreateEventRequest nextReq = CreateEventRequest.builder()
                .eventType("NEXT_VALID_EVENT")
                .actorId("ingest_user")
                .resourceType("RESOURCE")
                .resourceId("RES-3")
                .payload(Map.of("val", 200))
                .build();
        AuditRecord rec2 = auditLogService.createEvent(nextReq);

        // Verify sequence continuity: rec2 sequence must be rec1 sequence + 1
        assertEquals(rec1.getSequenceNumber() + 1, rec2.getSequenceNumber(), "Sequence must be strictly continuous without gaps from failed transactions");
        assertEquals(rec1.getRecordHash(), rec2.getPreviousHash(), "Hash chain link must connect directly to prior valid HEAD");

        // Verify overall chain integrity
        VerificationResult result = auditLogService.verifyChain();
        assertTrue(result.isIntact(), "Audit chain must remain intact following transaction failure rollback");
    }

    @Test
    @WithMockUser(username = "auditor_user", roles = {"AUDITOR"})
    @DisplayName("Phase 13: Querying non-existent checkpoint ID throws IllegalArgumentException")
    void testNonExistentCheckpointThrowsException() {
        assertThrows(IllegalArgumentException.class, () -> auditLogService.verifyCheckpoint("CHK-NON-EXISTENT-999"));
    }
}
