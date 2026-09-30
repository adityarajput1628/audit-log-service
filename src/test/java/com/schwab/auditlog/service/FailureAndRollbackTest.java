package com.schwab.auditlog.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.schwab.auditlog.crypto.HashChainEngine;
import com.schwab.auditlog.dto.CreateEventRequest;
import com.schwab.auditlog.dto.VerificationResult;
import com.schwab.auditlog.model.AuditRecord;
import com.schwab.auditlog.repository.AuditRecordRepository;
import com.schwab.auditlog.repository.ChainCheckpointRepository;
import com.schwab.auditlog.repository.IdempotencyRecordRepository;
import com.schwab.auditlog.security.SecurityEventLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.CannotAcquireLockException;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.*;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ActiveProfiles("test")
public class FailureAndRollbackTest {

    @Autowired
    private AuditLogService auditLogService;

    @Autowired
    private AuditRecordRepository auditRecordRepository;

    @Autowired
    private IdempotencyRecordRepository idempotencyRecordRepository;

    @Autowired
    private ChainCheckpointRepository chainCheckpointRepository;

    @Autowired
    private HashChainEngine hashChainEngine;

    @Autowired
    private SecurityEventLogger securityEventLogger;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private PlatformTransactionManager transactionManager;

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

    @Test
    @WithMockUser(username = "ingest_user", roles = {"INGEST"})
    @DisplayName("Deeper Failure Test A: Mid-way transaction exception rolls back cleanly with zero chain corruption")
    void testMidWayTransactionExceptionRollbackSafety() {
        long countBefore = auditRecordRepository.count();

        // Create initial valid event
        CreateEventRequest initReq = CreateEventRequest.builder()
                .eventType("BEFORE_MIDWAY_FAILURE")
                .actorId("ingest_user")
                .resourceType("ACCOUNT")
                .resourceId("ACC-100")
                .payload(Map.of("status", "ACTIVE"))
                .build();
        AuditRecord recordBefore = auditLogService.createEvent(initReq);

        // Build a mock repository that throws mid-way during saveAndFlush
        AuditRecordRepository mockRepo = Mockito.mock(AuditRecordRepository.class);
        Mockito.when(mockRepo.findLatestRecordForUpdate()).thenReturn(Optional.of(recordBefore));
        Mockito.when(mockRepo.saveAndFlush(Mockito.any())).thenThrow(new RuntimeException("Simulated database write failure mid-transaction"));

        AuditLogService customService = new AuditLogService(
                mockRepo, chainCheckpointRepository, idempotencyRecordRepository,
                hashChainEngine, objectMapper, transactionManager, securityEventLogger
        );

        CreateEventRequest failingReq = CreateEventRequest.builder()
                .eventType("MIDWAY_FAILING_EVENT")
                .actorId("ingest_user")
                .resourceType("ACCOUNT")
                .resourceId("ACC-101")
                .payload(Map.of("status", "PENDING"))
                .build();

        IllegalStateException ex = assertThrows(IllegalStateException.class, () ->
                customService.createEvent(failingReq, "MIDWAY-KEY-123")
        );
        assertTrue(ex.getMessage().contains("Failed to ingest audit event after 15 database transaction retries"),
                "Should cite 15 retries before failing fast");

        // Verify database state: no orphan records, no idempotency key persisted
        assertEquals(countBefore + 1, auditRecordRepository.count(), "Record count must equal count before failed attempt");
        assertTrue(idempotencyRecordRepository.findByIdempotencyKey("MIDWAY-KEY-123").isEmpty());

        // Subsequent valid record continues without sequence gap
        CreateEventRequest afterReq = CreateEventRequest.builder()
                .eventType("AFTER_MIDWAY_FAILURE")
                .actorId("ingest_user")
                .resourceType("ACCOUNT")
                .resourceId("ACC-102")
                .payload(Map.of("status", "COMPLETED"))
                .build();
        AuditRecord recordAfter = auditLogService.createEvent(afterReq);

        assertEquals(recordBefore.getSequenceNumber() + 1, recordAfter.getSequenceNumber());
        assertEquals(recordBefore.getRecordHash(), recordAfter.getPreviousHash());
        assertTrue(auditLogService.verifyChain().isIntact());
    }

    @Test
    @WithMockUser(username = "ingest_user", roles = {"INGEST"})
    @DisplayName("Deeper Failure Test B: Concurrent callers racing for same idempotency key create single record")
    void testConcurrentIdempotencyKeyRaceCondition() throws Exception {
        CreateEventRequest raceReq = CreateEventRequest.builder()
                .eventType("CONCURRENT_RACE_EVENT")
                .actorId("ingest_user")
                .resourceType("ORDER")
                .resourceId("ORD-999")
                .payload(Map.of("amount", 5000))
                .build();

        String idempotencyKey = "RACE-KEY-CONCURRENT-001";
        ExecutorService executor = Executors.newFixedThreadPool(2);
        CountDownLatch startLatch = new CountDownLatch(1);

        Callable<AuditRecord> task = () -> {
            startLatch.await();
            return auditLogService.createEvent(raceReq, idempotencyKey);
        };

        Future<AuditRecord> future1 = executor.submit(task);
        Future<AuditRecord> future2 = executor.submit(task);

        startLatch.countDown(); // Release both threads simultaneously

        AuditRecord res1 = future1.get(10, TimeUnit.SECONDS);
        AuditRecord res2 = future2.get(10, TimeUnit.SECONDS);
        executor.shutdown();

        assertNotNull(res1);
        assertNotNull(res2);
        assertEquals(res1.getId(), res2.getId(), "Both callers must receive identical AuditRecord ID");
        assertEquals(res1.getSequenceNumber(), res2.getSequenceNumber(), "Sequence numbers must match");
        assertEquals(res1.getRecordHash(), res2.getRecordHash(), "Record hashes must match");

        // Assert exactly 1 record was created in repository for this event
        long matchingRecords = auditRecordRepository.findAll().stream()
                .filter(r -> "ORD-999".equals(r.getResourceId()))
                .count();
        assertEquals(1, matchingRecords, "Only 1 AuditRecord must be created despite concurrent race");
    }

    @Test
    @WithMockUser(username = "ingest_user", roles = {"INGEST"})
    @DisplayName("Deeper Failure Test C: Pessimistic-lock retry budget exhaustion throws clear typed IllegalStateException")
    void testPessimisticLockRetryBudgetExhaustion() {
        AuditRecordRepository mockRepo = Mockito.mock(AuditRecordRepository.class);
        Mockito.when(mockRepo.findLatestRecordForUpdate())
                .thenThrow(new CannotAcquireLockException("Simulated pessimistic lock timeout exception"));

        AuditLogService customService = new AuditLogService(
                mockRepo, chainCheckpointRepository, idempotencyRecordRepository,
                hashChainEngine, objectMapper, transactionManager, securityEventLogger
        );

        CreateEventRequest lockReq = CreateEventRequest.builder()
                .eventType("LOCK_TIMEOUT_EVENT")
                .actorId("ingest_user")
                .resourceType("LOCK")
                .resourceId("LOCK-1")
                .payload(Map.of("test", "timeout"))
                .build();

        IllegalStateException ex = assertThrows(IllegalStateException.class, () ->
                customService.createEvent(lockReq)
        );

        assertTrue(ex.getMessage().contains("Failed to ingest audit event after 15 database transaction retries"),
                "Must throw clear typed IllegalStateException citing retry budget exhaustion");
        assertTrue(ex.getCause() instanceof CannotAcquireLockException,
                "Root cause must preserve the underlying CannotAcquireLockException");
    }
}
