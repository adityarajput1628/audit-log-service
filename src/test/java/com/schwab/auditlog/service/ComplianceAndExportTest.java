package com.schwab.auditlog.service;

import com.schwab.auditlog.dto.ComplianceReport;
import com.schwab.auditlog.dto.CreateEventRequest;
import com.schwab.auditlog.dto.ExportBundle;
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
class ComplianceAndExportTest {

    @Autowired
    private AuditLogService auditLogService;

    @Autowired
    private ExportService exportService;

    @Autowired
    private ComplianceService complianceService;

    @Autowired
    private AuditRecordRepository repository;

    @BeforeEach
    void setUp() {
        repository.deleteAll();
    }

    @Test
    @DisplayName("Verifiable bulk export should build self-contained bundle with digest")
    void testVerifiableExportBundle() {
        auditLogService.createEvent(CreateEventRequest.builder()
                .eventType("CLIENT_ACCOUNT_ACCESS")
                .actorId("advisor-tom")
                .resourceType("CLIENT_ACCOUNT")
                .resourceId("ACCT-7711")
                .payload(Map.of("action", "VIEW_BALANCE"))
                .build());

        ExportBundle bundle = exportService.generateExportBundle("ACCT-7711", null);

        assertThat(bundle.getFilterValue()).isEqualTo("ACCT-7711");
        assertThat(bundle.getRecordCount()).isEqualTo(1L);
        assertThat(bundle.getExportDigest()).hasSize(64);
        assertThat(bundle.getVerificationStatus()).isEqualTo("VERIFIED_INTACT");
    }

    @Test
    @DisplayName("Scenario C compliance report should aggregate access events and generate cryptographic proof")
    void testComplianceReportGeneration() {
        auditLogService.createEvent(CreateEventRequest.builder()
                .eventType("CLIENT_ACCOUNT_ACCESS")
                .actorId("compliance-officer-sarah")
                .resourceType("CLIENT_ACCOUNT")
                .resourceId("ACCT-7711")
                .payload(Map.of("purpose", "SEC_REGULATORY_AUDIT"))
                .build());

        ComplianceReport report = complianceService.generateClientAccessReport("ACCT-7711", null, null);

        assertThat(report.getClientAccountId()).isEqualTo("ACCT-7711");
        assertThat(report.getTotalAccessEvents()).isEqualTo(1L);
        assertThat(report.getUniqueActors()).isEqualTo(1L);
        assertThat(report.getCryptographicProofToken()).startsWith("PROOF-SHA256:");
        assertThat(report.getChainVerification().isIntact()).isTrue();
    }
}
