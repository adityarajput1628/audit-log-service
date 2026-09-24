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
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
class SecurityAndAuthorizationComprehensiveTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @org.springframework.beans.factory.annotation.Value("${schwab.security.users.ingest.username}")
    private String ingestUser;

    @org.springframework.beans.factory.annotation.Value("${schwab.security.users.ingest.password}")
    private String ingestPass;

    @Test
    @DisplayName("SEC-01: Unauthenticated requests return 401 Unauthorized across all protected API routes")
    void testUnauthenticatedAccessReturns401() throws Exception {
        mockMvc.perform(get("/api/v1/audit/events"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401));

        mockMvc.perform(get("/api/v1/audit/verify"))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(get("/api/v1/audit/export"))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(get("/api/v1/compliance/client-access-report"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("SEC-02: Invalid credentials return 401 Unauthorized")
    void testInvalidCredentialsReturn401() throws Exception {
        mockMvc.perform(get("/api/v1/audit/events")
                .with(httpBasic("admin", "invalid_password_token")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("SEC-03: RBAC role isolation prevents INGEST role from executing ADMIN operations")
    void testIngestRoleCannotExecuteAdminActions() throws Exception {
        RedactFieldRequest redactReq = new RedactFieldRequest("ssn", "Compliance redaction");
        mockMvc.perform(post("/api/v1/audit/events/1/redact")
                .with(httpBasic(ingestUser, ingestPass))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(redactReq)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status").value(403));

        RetentionRequest retentionReq = new RetentionRequest(30, false);
        mockMvc.perform(post("/api/v1/audit/retention/apply")
                .with(httpBasic(ingestUser, ingestPass))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(retentionReq)))
                .andExpect(status().isForbidden());

        mockMvc.perform(get("/api/v1/audit/export")
                .with(httpBasic(ingestUser, ingestPass))
                .param("actorId", ingestUser))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("SEC-04: BOLA/IDOR protection - INGEST role restricted to own actor queries")
    void testBolaResourceAuthorizationForNonAuditor() throws Exception {
        mockMvc.perform(get("/api/v1/audit/events")
                .with(httpBasic(ingestUser, ingestPass))
                .param("actorId", "unauthorized_actor_99"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status").value(403));
    }

    @Test
    @DisplayName("SEC-05: CORS policy enforces configured origin restrictions during preflight OPTIONS requests")
    void testCorsPreflightAllowedOrigins() throws Exception {
        mockMvc.perform(options("/api/v1/audit/events")
                .header("Origin", "http://localhost:8080")
                .header("Access-Control-Request-Method", "POST"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", "http://localhost:8080"));
    }

    @Test
    @DisplayName("SEC-06: CSRF protection stateless policy permits header-authenticated REST requests without session tokens")
    void testStatelessCsrfHeaderAuth() throws Exception {
        CreateEventRequest request = CreateEventRequest.builder()
                .eventType("SECURITY_AUDIT")
                .actorId(ingestUser)
                .resourceType("AUTH")
                .resourceId("SEC-100")
                .payload(Map.of("status", "VALID"))
                .build();

        mockMvc.perform(post("/api/v1/audit/events")
                .with(httpBasic(ingestUser, ingestPass))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated());
    }
}
