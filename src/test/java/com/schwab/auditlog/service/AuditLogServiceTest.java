package com.schwab.auditlog.service;

import com.schwab.auditlog.dto.CreateEventRequest;
import com.schwab.auditlog.dto.VerificationResult;
import com.schwab.auditlog.model.AuditRecord;
import com.schwab.auditlog.repository.AuditRecordRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
class AuditLogServiceTest {

    @Autowired
    private AuditLogService auditLogService;

    @Autowired
    private AuditRecordRepository repository;

    @BeforeEach
    void setUp() {
        repository.deleteAll();
    }

    @Test
    @DisplayName("Create event should assign sequence 1 and genesis previous hash to first record")
    void testCreateEventFirstRecord() {
        CreateEventRequest request = CreateEventRequest.builder()
                .eventType("USER_LOGIN")
                .actorId("actor-001")
                .resourceType("AUTH")
                .resourceId("SES-100")
                .payload(Map.of("browser", "Chrome"))
                .build();

        AuditRecord record = auditLogService.createEvent(request);

        assertThat(record.getSequenceNumber()).isEqualTo(1L);
        assertThat(record.getPreviousHash()).isEqualTo(AuditRecord.GENESIS_HASH);
        assertThat(record.getRecordHash()).hasSize(64);
    }

    @Test
    @DisplayName("Multiple events should form a connected SHA-256 hash chain")
    void testHashChainContinuity() {
        AuditRecord record1 = auditLogService.createEvent(CreateEventRequest.builder()
                .eventType("USER_LOGIN")
                .actorId("actor-001")
                .resourceType("AUTH")
                .resourceId("SES-100")
                .payload(Map.of("step", 1))
                .build());

        AuditRecord record2 = auditLogService.createEvent(CreateEventRequest.builder()
                .eventType("RECORD_UPDATED")
                .actorId("actor-001")
                .resourceType("ACCOUNT")
                .resourceId("ACC-550")
                .payload(Map.of("step", 2))
                .build());

        assertThat(record2.getSequenceNumber()).isEqualTo(2L);
        assertThat(record2.getPreviousHash()).isEqualTo(record1.getRecordHash());

        VerificationResult verification = auditLogService.verifyChain();
        assertThat(verification.isIntact()).isTrue();
        assertThat(verification.getTotalRecordsChecked()).isEqualTo(2L);
    }

    @Test
    @DisplayName("Direct database tampering should be detected by verification engine")
    void testTamperDetection() {
        AuditRecord record = auditLogService.createEvent(CreateEventRequest.builder()
                .eventType("PERMISSION_GRANTED")
                .actorId("admin-john")
                .resourceType("ROLE")
                .resourceId("ROLE_SUPER")
                .payload(Map.of("approved", true))
                .build());

        // Simulate direct database tampering
        auditLogService.simulateTampering(record.getId(), "{\"approved\":false, \"HACKED\":true}", null);

        VerificationResult verification = auditLogService.verifyChain();
        assertThat(verification.isIntact()).isFalse();
        assertThat(verification.getViolations()).hasSize(1);
        assertThat(verification.getViolations().get(0).getViolationType()).isEqualTo("HASH_MISMATCH");
    }
}
