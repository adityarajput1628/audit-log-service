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
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
public class AdversarialIntegrityTestSuiteTest {

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
    @DisplayName("Case A: Adversarial mutation of actorId causes cryptographic verification failure")
    void testCaseA_mutateActorId_causesVerificationFailure() {
        AuditRecord record = auditLogService.createEvent(CreateEventRequest.builder()
                .eventType("TRANSFER")
                .actorId("alice")
                .resourceType("ACCOUNT")
                .resourceId("ACC-100")
                .payload(Map.of("amount", 5000))
                .build());

        VerificationResult beforeTamper = auditLogService.verifyChain();
        assertTrue(beforeTamper.isIntact(), "Chain should initially be intact");

        // Adversary directly alters actorId in DB
        auditLogService.simulateTampering(record.getSequenceNumber(), null, "mallory");

        VerificationResult afterTamper = auditLogService.verifyChain();
        assertFalse(afterTamper.isIntact(), "Chain verification MUST fail after mutating actorId");
        assertEquals("HASH_MISMATCH", afterTamper.getViolations().get(0).getViolationType());
    }

    @Test
    @DisplayName("Case B: Adversarial mutation of archived payload causes verification failure")
    void testCaseB_mutateArchivedPayload_causesVerificationFailure() {
        AuditRecord record = auditLogService.createEvent(CreateEventRequest.builder()
                .eventType("TRADE")
                .actorId("bob")
                .resourceType("PORTFOLIO")
                .resourceId("FOL-200")
                .payload(Map.of("symbol", "AAPL", "qty", 100))
                .build());

        // Archive the record
        retentionService.applyRetentionPolicy(new RetentionRequest(-1, false));

        AuditRecord archivedRecord = repository.findById(record.getSequenceNumber()).orElseThrow();
        assertTrue(archivedRecord.isArchived(), "Record must be archived");

        VerificationResult beforeTamper = auditLogService.verifyChain();
        assertTrue(beforeTamper.isIntact(), "Archived chain should be intact");

        // Adversary mutates payloadJson of archived record
        archivedRecord.setPayloadJson("{\"symbol\":\"AAPL\",\"qty\":999999}");
        repository.save(archivedRecord);

        VerificationResult afterTamper = auditLogService.verifyChain();
        assertFalse(afterTamper.isIntact(), "Chain verification MUST fail after mutating archived payloadJson");
    }

    @Test
    @DisplayName("Case C: Adversarial mutation of metadata (eventType / resourceId) causes verification failure")
    void testCaseC_mutateMetadata_causesVerificationFailure() {
        AuditRecord record = auditLogService.createEvent(CreateEventRequest.builder()
                .eventType("LOGOUT")
                .actorId("charlie")
                .resourceType("SESSION")
                .resourceId("SES-999")
                .payload(Map.of("status", "SUCCESS"))
                .build());

        assertTrue(auditLogService.verifyChain().isIntact());

        // Adversary alters metadata resourceId directly in database
        record.setResourceId("SES-000-TAMPERED");
        repository.save(record);

        VerificationResult result = auditLogService.verifyChain();
        assertFalse(result.isIntact(), "Chain verification MUST fail when event metadata is mutated");
    }

    @Test
    @DisplayName("Case D: Adversarial mutation of digest/recordHash causes verification failure")
    void testCaseD_mutateDigest_causesVerificationFailure() {
        AuditRecord r1 = auditLogService.createEvent(CreateEventRequest.builder()
                .eventType("DEPOSIT")
                .actorId("dave")
                .resourceType("ACC")
                .resourceId("ACC-1")
                .payload(Map.of("val", 100))
                .build());

        AuditRecord r2 = auditLogService.createEvent(CreateEventRequest.builder()
                .eventType("WITHDRAW")
                .actorId("dave")
                .resourceType("ACC")
                .resourceId("ACC-1")
                .payload(Map.of("val", 50))
                .build());

        assertTrue(auditLogService.verifyChain().isIntact());

        // Adversary mutates the recordHash digest of record 1
        r1.setRecordHash("0000000000000000000000000000000000000000000000000000000000000000");
        repository.save(r1);

        VerificationResult result = auditLogService.verifyChain();
        assertFalse(result.isIntact(), "Chain verification MUST fail when record hash digest is mutated");
    }

    @Test
    @DisplayName("Case E: Attempt to bypass archived verification fails and reports tampering")
    void testCaseE_attemptToBypassArchivedVerification_causesVerificationFailure() {
        AuditRecord r1 = auditLogService.createEvent(CreateEventRequest.builder()
                .eventType("INIT")
                .actorId("eve")
                .resourceType("SYS")
                .resourceId("SYS-1")
                .payload(Map.of("key", "val"))
                .build());

        // Archive record
        retentionService.applyRetentionPolicy(new RetentionRequest(-1, false));

        AuditRecord archived = repository.findById(r1.getSequenceNumber()).orElseThrow();

        // Adversary attempts to forge payload AND insert fake _ARCHIVED_PAYLOAD redaction entry attempting a bypass
        archived.setPayloadJson("{\"key\":\"tampered_val\"}");
        archived.setRedactionsJson("{\"_ARCHIVED_PAYLOAD\":{\"salt\":\"fake\",\"fieldHash\":\"fakehash\"}}");
        repository.save(archived);

        VerificationResult result = auditLogService.verifyChain();
        assertFalse(result.isIntact(), "Chain verification MUST fail when attempting shortcut archived payload bypass");
    }
}

