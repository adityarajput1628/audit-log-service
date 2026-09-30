package com.schwab.auditlog.service;

import com.schwab.auditlog.dto.CreateEventRequest;
import com.schwab.auditlog.dto.RetentionRequest;
import com.schwab.auditlog.dto.VerificationResult;
import com.schwab.auditlog.model.AuditRecord;
import com.schwab.auditlog.model.ChainCheckpoint;
import com.schwab.auditlog.repository.AuditRecordRepository;
import com.schwab.auditlog.repository.ChainCheckpointRepository;
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
public class ExternalCheckpointTest {

    @Autowired
    private AuditLogService auditLogService;

    @Autowired
    private RetentionService retentionService;

    @Autowired
    private ChainCheckpointRepository checkpointRepository;

    @Autowired
    private AuditRecordRepository auditRecordRepository;

    @Test
    @WithMockUser(username = "admin_user", roles = {"ADMIN"})
    @DisplayName("Phase 2: Valid external checkpoint created and verified against ledger")
    void testValidCheckpointCreationAndVerification() {
        CreateEventRequest req = CreateEventRequest.builder()
                .eventType("FUND_TRANSFER")
                .actorId("admin_user")
                .resourceType("ACCOUNT")
                .resourceId("ACC-999")
                .payload(Map.of("amount", 5000))
                .build();
        auditLogService.createEvent(req);

        ChainCheckpoint checkpoint = auditLogService.createCheckpoint();
        assertNotNull(checkpoint.getCheckpointId());
        assertNotNull(checkpoint.getSignature());
        assertEquals("VALID", checkpoint.getStatus());

        VerificationResult verifyResult = auditLogService.verifyCheckpoint(checkpoint.getCheckpointId());
        assertTrue(verifyResult.isIntact(), "Valid external checkpoint verification must return intact");
        assertEquals(0, verifyResult.getViolations().size());
    }

    @Test
    @WithMockUser(username = "admin_user", roles = {"ADMIN"})
    @DisplayName("Phase 2: Checkpoint verification fails when chain head record hash is tampered in database")
    void testTamperedChainHeadCausesCheckpointMismatch() {
        CreateEventRequest req = CreateEventRequest.builder()
                .eventType("SECURITY_ALERT")
                .actorId("admin_user")
                .resourceType("SYSTEM")
                .resourceId("SYS-1")
                .payload(Map.of("severity", "HIGH"))
                .build();
        AuditRecord record = auditLogService.createEvent(req);

        ChainCheckpoint checkpoint = auditLogService.createCheckpoint();

        // Simulate database tampering on the head record
        record.setPayloadJson("{\"severity\":\"CORRUPTED\"}");
        auditRecordRepository.saveAndFlush(record);

        VerificationResult verifyResult = auditLogService.verifyCheckpoint(checkpoint.getCheckpointId());
        assertFalse(verifyResult.isIntact(), "Checkpoint verification must fail when chain head is tampered");
        assertTrue(verifyResult.getViolations().stream().anyMatch(v -> v.getViolationType().contains("CHECKPOINT") || v.getViolationType().contains("HASH_MISMATCH")));
    }

    @Test
    @WithMockUser(username = "admin_user", roles = {"ADMIN"})
    @DisplayName("Phase 2: Checkpoint verification fails when checkpoint signature is tampered")
    void testTamperedCheckpointSignatureFailsVerification() {
        CreateEventRequest req = CreateEventRequest.builder()
                .eventType("SYSTEM_UPDATE")
                .actorId("admin_user")
                .resourceType("CONFIG")
                .resourceId("CFG-100")
                .payload(Map.of("version", "2.0"))
                .build();
        auditLogService.createEvent(req);

        ChainCheckpoint checkpoint = auditLogService.createCheckpoint();
        checkpoint.setSignature("bad_forged_signature_hex_code_1234567890");
        checkpointRepository.saveAndFlush(checkpoint);

        VerificationResult verifyResult = auditLogService.verifyCheckpoint(checkpoint.getCheckpointId());
        assertFalse(verifyResult.isIntact(), "Tampered checkpoint signature must be caught");
        assertTrue(verifyResult.getViolations().stream().anyMatch(v -> "CHECKPOINT_SIGNATURE_TAMPERED".equals(v.getViolationType())));
    }

    @Test
    @WithMockUser(username = "admin_user", roles = {"ADMIN"})
    @DisplayName("Phase 2 & Phase 1: Retention followed by checkpoint verification passes cleanly")
    void testRetentionFollowedByCheckpointVerification() {
        CreateEventRequest req = CreateEventRequest.builder()
                .eventType("LOGIN")
                .actorId("admin_user")
                .resourceType("SESSION")
                .resourceId("SESS-1")
                .payload(Map.of("ip", "10.0.0.1"))
                .build();
        auditLogService.createEvent(req);

        retentionService.applyRetentionPolicy(RetentionRequest.builder().retentionWindowDays(30).dryRun(false).build());

        ChainCheckpoint checkpoint = auditLogService.createCheckpoint();
        VerificationResult verifyResult = auditLogService.verifyCheckpoint(checkpoint.getCheckpointId());
        assertTrue(verifyResult.isIntact(), "Checkpoint verification must succeed after retention policy execution");
    }
}
