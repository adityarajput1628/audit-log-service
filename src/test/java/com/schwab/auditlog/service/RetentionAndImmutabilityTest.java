package com.schwab.auditlog.service;

import com.schwab.auditlog.dto.CreateEventRequest;
import com.schwab.auditlog.dto.RetentionRequest;
import com.schwab.auditlog.dto.VerificationResult;
import com.schwab.auditlog.model.AuditRecord;
import com.schwab.auditlog.repository.AuditRecordRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
public class RetentionAndImmutabilityTest {

    @Autowired
    private AuditLogService auditLogService;

    @Autowired
    private RetentionService retentionService;

    @Autowired
    private AuditRecordRepository repository;

    @Test
    @WithMockUser(username = "admin_user", roles = {"ADMIN"})
    @DisplayName("ARCH-03: Retention appends tombstones without modifying historical record hashes or payloads")
    void testRetentionImmutabilityAndTombstone() {
        // Create initial historical record
        CreateEventRequest req1 = CreateEventRequest.builder()
                .eventType("USER_LOGIN")
                .actorId("admin_user")
                .resourceType("ACCOUNT")
                .resourceId("ACC-1001")
                .payload(Map.of("ip", "192.168.1.1", "device", "browser"))
                .timestamp(Instant.now().minusSeconds(86400 * 40)) // 40 days old
                .build();

        AuditRecord r1 = auditLogService.createEvent(req1);
        String originalPayload = r1.getPayloadJson();
        String originalRecordHash = r1.getRecordHash();
        String originalPreviousHash = r1.getPreviousHash();
        Long originalSequence = r1.getSequenceNumber();

        // Run retention policy (30 days window)
        RetentionRequest retentionRequest = RetentionRequest.builder()
                .retentionWindowDays(30)
                .dryRun(false)
                .build();

        Map<String, Object> result = retentionService.applyRetentionPolicy(retentionRequest);
        assertEquals(false, result.get("dryRun"));
        assertTrue((Integer) result.get("archivedCount") >= 1);

        // Verify original record fields remain 100% immutable
        AuditRecord fetchedR1 = repository.findById(r1.getId()).orElseThrow();
        assertEquals(originalPayload, fetchedR1.getPayloadJson(), "Original payload must remain completely intact!");
        assertEquals(originalRecordHash, fetchedR1.getRecordHash(), "Original recordHash must NOT be recomputed!");
        assertEquals(originalPreviousHash, fetchedR1.getPreviousHash(), "Original previousHash must NOT be changed!");
        assertEquals(originalSequence, fetchedR1.getSequenceNumber(), "Original sequence number must NOT change!");

        // Verify a new RETENTION_TOMBSTONE event was appended
        List<AuditRecord> allRecords = repository.findAllByOrderBySequenceNumberAsc();
        assertTrue(allRecords.size() >= 2, "Tombstone event must be appended to the ledger");

        AuditRecord tombstoneRecord = allRecords.get(allRecords.size() - 1);
        assertEquals("RETENTION_TOMBSTONE", tombstoneRecord.getEventType());
        assertTrue(tombstoneRecord.getPayloadJson().contains("targetOriginalHash"));
        assertEquals(r1.getRecordHash(), tombstoneRecord.getPreviousHash(), "Tombstone must link to previous HEAD hash");

        // Verify entire audit chain remains 100% cryptographically intact
        VerificationResult chainResult = auditLogService.verifyChain();
        assertTrue(chainResult.isIntact(), "Hash chain must remain intact after retention tombstone appending");
        assertEquals(0, chainResult.getViolations().size());
    }
}
