package com.schwab.auditlog.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.schwab.auditlog.dto.CreateEventRequest;
import com.schwab.auditlog.model.AuditRecord;
import com.schwab.auditlog.repository.AuditRecordRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
public class ValidationAndSerializationFailureTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private AuditLogService auditLogService;

    @Autowired
    private AuditRecordRepository repository;

    @org.springframework.beans.factory.annotation.Value("${schwab.security.users.ingest.username}")
    private String ingestUser;

    @org.springframework.beans.factory.annotation.Value("${schwab.security.users.ingest.password}")
    private String ingestPass;

    @BeforeEach
    void setUp() {
        repository.deleteAll();
    }

    @Test
    @DisplayName("VAL-01: Invalid event request with blank eventType fails validation (400 Bad Request)")
    void testBlankEventTypeFailsValidation() throws Exception {
        CreateEventRequest invalidReq = CreateEventRequest.builder()
                .eventType("") // Blank
                .actorId("actor-1")
                .resourceType("ACCOUNT")
                .resourceId("ACC-1")
                .payload(Map.of("val", 100))
                .build();

        mockMvc.perform(post("/api/v1/audit/events")
                .with(httpBasic(ingestUser, ingestPass))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(invalidReq)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("VAL-02: Query events with 'from' timestamp after 'to' timestamp throws IllegalArgumentException")
    void testQueryEventsWithInvalidTimeRangeThrowsException() {
        Instant now = Instant.now();
        Instant past = now.minusSeconds(3600);

        assertThrows(IllegalArgumentException.class, () ->
                auditLogService.queryEvents(null, null, null, null, now, past, false, 0, 10)
        );
    }

    @Test
    @DisplayName("VAL-03: Null CreateEventRequest throws IllegalArgumentException")
    void testNullCreateEventRequestThrowsException() {
        assertThrows(IllegalArgumentException.class, () ->
                auditLogService.createEvent(null)
        );
    }

    @Test
    @DisplayName("VAL-04: Non-existent audit record query returns empty optional")
    void testGetNonExistentRecord() {
        var opt = auditLogService.getById(999999L);
        org.junit.jupiter.api.Assertions.assertTrue(opt.isEmpty());
    }
}
