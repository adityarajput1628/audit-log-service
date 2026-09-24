package com.schwab.auditlog.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.schwab.auditlog.AuditLogServiceApplication;
import com.schwab.auditlog.crypto.HashChainEngine;
import com.schwab.auditlog.dto.CreateEventRequest;
import com.schwab.auditlog.dto.RedactFieldRequest;
import com.schwab.auditlog.dto.RetentionRequest;
import com.schwab.auditlog.exception.AuditSecurityException;
import com.schwab.auditlog.exception.AuditSerializationException;
import com.schwab.auditlog.exception.GlobalExceptionHandler;
import com.schwab.auditlog.model.AuditRecord;
import com.schwab.auditlog.repository.AuditRecordRepository;
import jakarta.validation.ConstraintViolationException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;

import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
class DetailedCoverageExpansionTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private AuditLogService auditLogService;

    @Autowired
    private RedactionService redactionService;

    @Autowired
    private RetentionService retentionService;

    @Autowired
    private AuditRecordRepository repository;

    @org.springframework.beans.factory.annotation.Value("${schwab.security.users.ingest.username}")
    private String ingestUser;

    @org.springframework.beans.factory.annotation.Value("${schwab.security.users.ingest.password}")
    private String ingestPass;

    @org.springframework.beans.factory.annotation.Value("${schwab.security.users.auditor.username}")
    private String auditorUser;

    @org.springframework.beans.factory.annotation.Value("${schwab.security.users.auditor.password}")
    private String auditorPass;

    @Test
    @DisplayName("RedactionService: Redacting an already archived record throws IllegalStateException")
    void testRedactingArchivedRecordThrowsException() {
        CreateEventRequest request = CreateEventRequest.builder()
                .eventType("LOGIN")
                .actorId("actor-redact-archived")
                .resourceType("ACCOUNT")
                .resourceId("ACC-999")
                .payload(Map.of("ssn", "123-45-6789"))
                .build();

        AuditRecord record = auditLogService.createEvent(request);
        retentionService.applyRetentionPolicy(new RetentionRequest(0, false)); // Archive all records

        RedactFieldRequest redactReq = new RedactFieldRequest("ssn", "Post-archive redaction attempt");

        IllegalStateException ex = assertThrows(IllegalStateException.class, () ->
                redactionService.redactPayloadField(record.getId(), redactReq));

        assertTrue(ex.getMessage().contains("archived record"));
    }

    @Test
    @DisplayName("RedactionService: Redacting non-existent field path throws IllegalArgumentException")
    void testRedactingNonExistentFieldThrowsException() {
        CreateEventRequest request = CreateEventRequest.builder()
                .eventType("TRANSFER")
                .actorId("actor-invalid-path")
                .resourceType("ACCOUNT")
                .resourceId("ACC-888")
                .payload(Map.of("amount", 5000))
                .build();

        AuditRecord record = auditLogService.createEvent(request);
        RedactFieldRequest redactReq = new RedactFieldRequest("non_existent_key", "Invalid path redaction");

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
                redactionService.redactPayloadField(record.getId(), redactReq));

        assertTrue(ex.getMessage().contains("not found in payload"));
    }

    @Test
    @DisplayName("RedactionService: Redacting nested map field path (e.g. user.address.zipcode)")
    void testRedactNestedFieldPath() {
        CreateEventRequest request = CreateEventRequest.builder()
                .eventType("UPDATE_PROFILE")
                .actorId("actor-nested")
                .resourceType("USER_PROFILE")
                .resourceId("USR-101")
                .payload(Map.of("user", Map.of("address", Map.of("zipcode", "90210", "city", "Los Angeles"))))
                .build();

        AuditRecord record = auditLogService.createEvent(request);
        RedactFieldRequest redactReq = new RedactFieldRequest("user.address.zipcode", "Redact ZIP");

        AuditRecord redacted = redactionService.redactPayloadField(record.getId(), redactReq);
        assertNotNull(redacted.getRedactionsJson());
        assertTrue(redacted.getPayloadJson().contains("[REDACTED]"));
    }

    @Test
    @DisplayName("ComplianceController: Missing clientAccountId parameter returns HTTP 400 Bad Request")
    void testComplianceControllerMissingClientAccountIdReturns400() throws Exception {
        mockMvc.perform(get("/api/v1/compliance/client-access-report")
                .with(httpBasic(auditorUser, auditorPass)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("ComplianceController: INGEST role calling compliance report returns HTTP 403 Forbidden")
    void testComplianceControllerIngestRoleForbidden() throws Exception {
        mockMvc.perform(get("/api/v1/compliance/client-access-report")
                .with(httpBasic(ingestUser, ingestPass))
                .param("clientAccountId", "ACC-777"))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("ComplianceController: AUDITOR role with valid clientAccountId returns HTTP 200 with report body")
    void testComplianceControllerAuditorReturns200() throws Exception {
        // Ingest one event first so the report has real data to summarize
        CreateEventRequest request = CreateEventRequest.builder()
                .eventType("ACCOUNT_ACCESS")
                .actorId(auditorUser)
                .resourceType("ACCOUNT")
                .resourceId("ACC-COMPLIANCE-TEST-1")
                .payload(Map.of("action", "VIEW"))
                .build();

        mockMvc.perform(post("/api/v1/audit/events")
                .with(httpBasic(ingestUser, ingestPass))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated());

        mockMvc.perform(get("/api/v1/compliance/client-access-report")
                .with(httpBasic(auditorUser, auditorPass))
                .param("clientAccountId", "ACC-COMPLIANCE-TEST-1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.clientAccountId").value("ACC-COMPLIANCE-TEST-1"))
                .andExpect(jsonPath("$.totalAccessEvents").value(1));
    }

    @Test
    @DisplayName("GlobalExceptionHandler: Direct invocation of exception handlers for complete coverage")
    void testGlobalExceptionHandlerDirectCoverage() {
        GlobalExceptionHandler handler = new GlobalExceptionHandler();

        // AccessDeniedException
        AccessDeniedException accessDenied = new AccessDeniedException("Denied");
        assertThrows(AccessDeniedException.class, () -> handler.handleAccessDenied(accessDenied));

        // AuthenticationException
        AuthenticationException authEx = new AuthenticationException("Auth Failed") {};
        assertThrows(AuthenticationException.class, () -> handler.handleAuthenticationException(authEx));

        // AuditSecurityException
        ResponseEntity<Map<String, Object>> resSecurity = handler.handleAuditSecurity(new AuditSecurityException("Security breach"));
        assertEquals(HttpStatus.FORBIDDEN, resSecurity.getStatusCode());
        assertEquals("Forbidden", resSecurity.getBody().get("error"));

        // AuditSerializationException
        ResponseEntity<Map<String, Object>> resSer = handler.handleAuditSerialization(new AuditSerializationException("JSON error", new RuntimeException()));
        assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, resSer.getStatusCode());

        // IllegalArgumentException
        ResponseEntity<Map<String, Object>> resArg = handler.handleIllegalArgument(new IllegalArgumentException("Bad arg"));
        assertEquals(HttpStatus.BAD_REQUEST, resArg.getStatusCode());

        // IllegalStateException
        ResponseEntity<Map<String, Object>> resState = handler.handleIllegalState(new IllegalStateException("Conflict state"));
        assertEquals(HttpStatus.CONFLICT, resState.getStatusCode());

        // ConstraintViolationException
        ConstraintViolationException cve = new ConstraintViolationException("Constraint violation message", Set.of());
        ResponseEntity<Map<String, Object>> resCve = handler.handleConstraintViolation(cve);
        assertEquals(HttpStatus.BAD_REQUEST, resCve.getStatusCode());

        // General Exception
        ResponseEntity<Map<String, Object>> resGen = handler.handleGeneralException(new RuntimeException("Unknown runtime error"));
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, resGen.getStatusCode());
    }
}
