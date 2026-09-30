package com.schwab.auditlog.service;

import com.schwab.auditlog.dto.CreateEventRequest;
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
public class IdempotencyAndReplayTest {

    @Autowired
    private AuditLogService auditLogService;

    @Autowired
    private AuditRecordRepository auditRecordRepository;

    @Autowired
    private IdempotencyRecordRepository idempotencyRecordRepository;

    @Test
    @WithMockUser(username = "ingest_user", roles = {"INGEST"})
    @DisplayName("Phase 5: First request with idempotency key creates event; retried identical request returns same event")
    void testNormalIdempotencyAndReplay() {
        String idempotencyKey = "IDEM-KEY-99999";

        CreateEventRequest req = CreateEventRequest.builder()
                .eventType("PAYMENT_INGESTED")
                .actorId("ingest_user")
                .resourceType("PAYMENT")
                .resourceId("PAY-1001")
                .payload(Map.of("amount", 250.0, "currency", "USD"))
                .build();

        AuditRecord firstRecord = auditLogService.createEvent(req, idempotencyKey);
        assertNotNull(firstRecord);
        assertNotNull(firstRecord.getId());

        long countAfterFirst = auditRecordRepository.count();

        // Retry exact same request with same idempotency key
        AuditRecord retriedRecord = auditLogService.createEvent(req, idempotencyKey);
        assertEquals(firstRecord.getId(), retriedRecord.getId(), "Retried request must return original AuditRecord instance");
        assertEquals(firstRecord.getRecordHash(), retriedRecord.getRecordHash());
        assertEquals(countAfterFirst, auditRecordRepository.count(), "Retried request must NOT create a second audit record");
    }

    @Test
    @WithMockUser(username = "ingest_user", roles = {"INGEST"})
    @DisplayName("Phase 5: Same idempotency key with conflicting payload is rejected with IllegalArgumentException")
    void testIdempotencyKeyConflictWithDifferentPayload() {
        String idempotencyKey = "IDEM-KEY-CONFLICT-1";

        CreateEventRequest originalReq = CreateEventRequest.builder()
                .eventType("ORDER_CANCELLED")
                .actorId("ingest_user")
                .resourceType("ORDER")
                .resourceId("ORD-500")
                .payload(Map.of("reason", "USER_REQUEST"))
                .build();

        auditLogService.createEvent(originalReq, idempotencyKey);

        CreateEventRequest conflictingReq = CreateEventRequest.builder()
                .eventType("ORDER_CANCELLED")
                .actorId("ingest_user")
                .resourceType("ORDER")
                .resourceId("ORD-500")
                .payload(Map.of("reason", "FRAUD_SUSPECTED")) // Different payload!
                .build();

        assertThrows(IllegalArgumentException.class, () -> auditLogService.createEvent(conflictingReq, idempotencyKey),
                "Reusing idempotency key with a conflicting payload must throw an error");
    }
}
