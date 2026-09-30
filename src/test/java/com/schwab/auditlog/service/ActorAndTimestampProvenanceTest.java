package com.schwab.auditlog.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.schwab.auditlog.dto.CreateEventRequest;
import com.schwab.auditlog.exception.AuditSecurityException;
import com.schwab.auditlog.model.AuditRecord;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
public class ActorAndTimestampProvenanceTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private AuditLogService auditLogService;

    @org.springframework.beans.factory.annotation.Value("${schwab.security.users.ingest.username}")
    private String ingestUser;

    @org.springframework.beans.factory.annotation.Value("${schwab.security.users.ingest.password}")
    private String ingestPass;

    @Test
    @WithMockUser(username = "ingest_service_user", roles = {"INGEST"})
    @DisplayName("Phase 3: Authenticated user creating event auto-assigns authenticated principal as actorId")
    void testAuthenticatedUserAutoAssignsActorId() {
        CreateEventRequest req = CreateEventRequest.builder()
                .eventType("ORDER_CREATED")
                .resourceType("ORDER")
                .resourceId("ORD-100")
                .payload(Map.of("symbol", "SCHW", "qty", 50))
                .build();

        AuditRecord created = auditLogService.createEvent(req);
        assertEquals("ingest_service_user", created.getActorId(), "Stored actorId must be derived from authenticated principal");
    }

    @Test
    @WithMockUser(username = "regular_user", roles = {"USER"})
    @DisplayName("Phase 3: Non-admin user attempting to spoof another user's actorId is rejected")
    void testActorSpoofingAttemptRejected() {
        CreateEventRequest req = CreateEventRequest.builder()
                .eventType("TRANSFER")
                .actorId("malicious_impersonated_user")
                .resourceType("ACCOUNT")
                .resourceId("ACC-555")
                .payload(Map.of("amount", 10000))
                .build();

        assertThrows(AuditSecurityException.class, () -> auditLogService.createEvent(req),
                "Non-admin caller attempting actorId spoofing must be rejected");
    }

    @Test
    @WithMockUser(username = "admin_super_user", roles = {"ADMIN"})
    @DisplayName("Phase 3: Admin user is permitted to specify target actorId")
    void testAdminPermittedToSpecifyActorId() {
        CreateEventRequest req = CreateEventRequest.builder()
                .eventType("ADMIN_ACTION")
                .actorId("target_user_account")
                .resourceType("PROFILE")
                .resourceId("PROF-12")
                .payload(Map.of("action", "RESET_PASSWORD"))
                .build();

        AuditRecord created = auditLogService.createEvent(req);
        assertEquals("target_user_account", created.getActorId(), "Admin caller should be permitted to specify target actorId");
    }

    @Test
    @DisplayName("Phase 4: Authoritative timestamp is generated server-side and caller cannot forge it over REST API")
    void testAuthoritativeServerTimestampRestApi() throws Exception {
        Instant forgedPastTimestamp = Instant.parse("2000-01-01T00:00:00Z");

        CreateEventRequest req = CreateEventRequest.builder()
                .eventType("TRADE_EXECUTION")
                .actorId(ingestUser)
                .resourceType("TRADE")
                .resourceId("TRD-77")
                .payload(Map.of("price", 150.5))
                .timestamp(forgedPastTimestamp)
                .build();

        mockMvc.perform(post("/api/v1/audit/events")
                .with(httpBasic(ingestUser, ingestPass))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.payloadJson").value(org.hamcrest.Matchers.containsString("_occurredAt")))
                .andExpect(jsonPath("$.timestamp").value(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("2000-01-01"))));
    }
}
