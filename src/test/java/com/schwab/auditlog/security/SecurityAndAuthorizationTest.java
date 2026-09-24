package com.schwab.auditlog.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.schwab.auditlog.dto.CreateEventRequest;
import com.schwab.auditlog.dto.RedactFieldRequest;
import com.schwab.auditlog.dto.RetentionRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
class SecurityAndAuthorizationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @org.springframework.beans.factory.annotation.Value("${schwab.security.users.ingest.username}")
    private String ingestUser;

    @org.springframework.beans.factory.annotation.Value("${schwab.security.users.ingest.password}")
    private String ingestPass;

    @org.springframework.beans.factory.annotation.Value("${schwab.security.users.auditor.username}")
    private String auditorUser;

    @org.springframework.beans.factory.annotation.Value("${schwab.security.users.auditor.password}")
    private String auditorPass;

    @org.springframework.beans.factory.annotation.Value("${schwab.security.users.admin.username}")
    private String adminUser;

    @org.springframework.beans.factory.annotation.Value("${schwab.security.users.admin.password}")
    private String adminPass;

    @Test
    @DisplayName("Unauthenticated requests to protected endpoints return 401 Unauthorized")
    void testUnauthenticatedAccessReturns401() throws Exception {
        CreateEventRequest request = CreateEventRequest.builder()
                .eventType("LOGIN")
                .actorId("actor-1")
                .resourceType("AUTH")
                .resourceId("SES-1")
                .payload(Map.of("user", "test"))
                .build();

        mockMvc.perform(post("/api/v1/audit/events")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.error").value("Unauthorized"));

        mockMvc.perform(get("/api/v1/audit/events"))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(get("/api/v1/audit/verify"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("INGEST user cannot call admin endpoints (403 Forbidden)")
    void testIngestRoleCannotAccessAdminEndpoints() throws Exception {
        RedactFieldRequest redactReq = new RedactFieldRequest("ssn", "GDPR compliance request");
        mockMvc.perform(post("/api/v1/audit/events/1/redact")
                .with(httpBasic(ingestUser, ingestPass))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(redactReq)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status").value(403))
                .andExpect(jsonPath("$.error").value("Forbidden"));

        RetentionRequest retentionReq = new RetentionRequest(30, false);
        mockMvc.perform(post("/api/v1/audit/retention/apply")
                .with(httpBasic(ingestUser, ingestPass))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(retentionReq)))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Authorized users can access endpoints according to assigned RBAC roles")
    void testAuthorizedUserAccess() throws Exception {
        CreateEventRequest request = CreateEventRequest.builder()
                .eventType("LOGIN")
                .actorId("actor-1")
                .resourceType("AUTH")
                .resourceId("SES-1")
                .payload(Map.of("user", "test"))
                .build();

        mockMvc.perform(post("/api/v1/audit/events")
                .with(httpBasic(ingestUser, ingestPass))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.sequenceNumber").value(1));

        mockMvc.perform(get("/api/v1/audit/verify")
                .with(httpBasic(auditorUser, auditorPass)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.intact").value(true));

        RetentionRequest retentionReq = new RetentionRequest(30, false);
        mockMvc.perform(post("/api/v1/audit/retention/apply")
                .with(httpBasic(adminUser, adminPass))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(retentionReq)))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("BOLA / IDOR protection: Non-auditors cannot query events belonging to other actors")
    void testBolaResourceAuthorization_nonAuditorCannotAccessOtherActorEvents() throws Exception {
        mockMvc.perform(get("/api/v1/audit/events")
                .with(httpBasic(ingestUser, ingestPass))
                .param("actorId", "other_user_account"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status").value(403))
                .andExpect(jsonPath("$.error").value("Forbidden"));
    }

    @Test
    @DisplayName("BOLA / IDOR protection: AUDITOR and ADMIN can access events for any actorId")
    void testAuditorCanAccessAnyActorEvents() throws Exception {
        mockMvc.perform(get("/api/v1/audit/events")
                .with(httpBasic(auditorUser, auditorPass))
                .param("actorId", "target_client_account"))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/v1/audit/events")
                .with(httpBasic(adminUser, adminPass))
                .param("actorId", "target_client_account"))
                .andExpect(status().isOk());
    }
}

