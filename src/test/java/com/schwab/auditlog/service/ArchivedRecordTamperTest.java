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
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
class ArchivedRecordTamperTest {

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
    @DisplayName("Archived record tampering must be caught by verifyChain()")
    void testArchivedRecordTamperingIsDetected() {
        Instant oldTime = Instant.now().minus(40, ChronoUnit.DAYS);
        CreateEventRequest req1 = CreateEventRequest.builder()
                .eventType("OLD_EVENT")
                .actorId("actor-001")
                .resourceType("ACCOUNT")
                .resourceId("ACC-100")
                .payload(Map.of("balance", 1000))
                .timestamp(oldTime)
                .build();

        AuditRecord r1 = auditLogService.createEvent(req1);

        CreateEventRequest req2 = CreateEventRequest.builder()
                .eventType("NEW_EVENT")
                .actorId("actor-002")
                .resourceType("ACCOUNT")
                .resourceId("ACC-100")
                .payload(Map.of("balance", 2000))
                .build();

        auditLogService.createEvent(req2);

        // Apply retention policy (archives records older than 30 days)
        retentionService.applyRetentionPolicy(new RetentionRequest(30, false));

        // Verify that initial archived chain is 100% intact
        VerificationResult initialVerify = auditLogService.verifyChain();
        assertThat(initialVerify.isIntact()).isTrue();
        assertThat(initialVerify.getArchivedRecordsChecked()).isEqualTo(1);

        // Directly tamper with the archived record in DB (mutate actorId metadata)
        AuditRecord archivedRecord = repository.findById(r1.getId()).orElseThrow();
        archivedRecord.setActorId("TAMPERED_ACTOR");
        repository.save(archivedRecord);

        // Verify that verifyChain() catches the archived record tampering!
        VerificationResult tamperedVerify = auditLogService.verifyChain();
        assertThat(tamperedVerify.isIntact()).isFalse();
        assertThat(tamperedVerify.getViolations()).hasSize(1);
        assertThat(tamperedVerify.getViolations().get(0).getViolationType()).isEqualTo("HASH_MISMATCH");
    }
}
