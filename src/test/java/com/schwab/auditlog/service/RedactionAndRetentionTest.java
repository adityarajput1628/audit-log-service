package com.schwab.auditlog.service;

import com.schwab.auditlog.dto.CreateEventRequest;
import com.schwab.auditlog.dto.RedactFieldRequest;
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
class RedactionAndRetentionTest {

    @Autowired
    private AuditLogService auditLogService;

    @Autowired
    private RedactionService redactionService;

    @Autowired
    private RetentionService retentionService;

    @Autowired
    private AuditRecordRepository repository;

    @BeforeEach
    void setUp() {
        repository.deleteAll();
    }

    @Test
    @DisplayName("Structured redaction should mask sensitive payload field without breaking hash chain")
    void testStructuredRedactionHashPreservation() {
        AuditRecord record = auditLogService.createEvent(CreateEventRequest.builder()
                .eventType("CLIENT_ACCOUNT_ACCESS")
                .actorId("advisor-jane")
                .resourceType("CLIENT_ACCOUNT")
                .resourceId("ACCT-8899")
                .payload(Map.of(
                        "clientName", "Robert Miller",
                        "accountNumber", "SCHW-773321",
                        "ssn", "999-00-1234"
                ))
                .build());

        String originalHash = record.getRecordHash();

        // Perform structured redaction on 'accountNumber'
        AuditRecord redactedRecord = redactionService.redactPayloadField(record.getId(), RedactFieldRequest.builder()
                .fieldPath("accountNumber")
                .reason("GDPR PII Data Privacy Request")
                .build());

        assertThat(redactedRecord.getPayloadJson()).contains("[REDACTED]");
        assertThat(redactedRecord.getPayloadJson()).doesNotContain("SCHW-773321");
        assertThat(redactedRecord.getRecordHash()).isEqualTo(originalHash);

        // Verify chain verification remains 100% INTACT
        VerificationResult verification = auditLogService.verifyChain();
        assertThat(verification.isIntact()).isTrue();
    }

    @Test
    @DisplayName("Retention policy should archive aged records while maintaining chain verification")
    void testRetentionPolicyArchiving() {
        // Create an aged record (30 days ago)
        Instant oldTimestamp = Instant.now().minus(30, ChronoUnit.DAYS).truncatedTo(ChronoUnit.MILLIS);
        AuditRecord oldRecord = auditLogService.createEvent(CreateEventRequest.builder()
                .eventType("STATEMENT_DOWNLOADED")
                .actorId("user-100")
                .resourceType("STATEMENT")
                .resourceId("STMT-2024")
                .payload(Map.of("period", "Q1"))
                .timestamp(oldTimestamp)
                .build());

        // Create a fresh record
        AuditRecord freshRecord = auditLogService.createEvent(CreateEventRequest.builder()
                .eventType("USER_LOGIN")
                .actorId("user-100")
                .resourceType("AUTH")
                .resourceId("SES-999")
                .payload(Map.of("ip", "10.0.0.1"))
                .build());

        // Apply retention policy for 7 days cutoff
        Map<String, Object> retentionResult = retentionService.applyRetentionPolicy(RetentionRequest.builder()
                .retentionWindowDays(7)
                .dryRun(false)
                .build());

        assertThat((Integer) retentionResult.get("archivedCount")).isEqualTo(1);

        // Check archived record tombstone state
        AuditRecord reloadedOld = repository.findById(oldRecord.getId()).orElseThrow();
        assertThat(reloadedOld.isArchived()).isTrue();
        assertThat(reloadedOld.getPayloadJson()).contains("_archived");

        // Chain verification must be 100% INTACT without false positive break
        VerificationResult verification = auditLogService.verifyChain();
        assertThat(verification.isIntact()).isTrue();
    }
}
