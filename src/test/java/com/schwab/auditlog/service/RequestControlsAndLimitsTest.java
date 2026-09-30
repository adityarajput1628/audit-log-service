package com.schwab.auditlog.service;

import com.schwab.auditlog.dto.CreateEventRequest;
import com.schwab.auditlog.model.AuditRecord;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
public class RequestControlsAndLimitsTest {

    @Autowired
    private AuditLogService auditLogService;

    @Test
    @WithMockUser(username = "ingest_user", roles = {"INGEST"})
    @DisplayName("Phase 6: Payload size exceeding limit (>256KB) throws IllegalArgumentException")
    void testOversizedPayloadRejected() {
        String largeString = "A".repeat(300 * 1024); // 300KB string
        CreateEventRequest req = CreateEventRequest.builder()
                .eventType("BULK_UPLOAD")
                .actorId("ingest_user")
                .resourceType("FILE")
                .resourceId("FILE-1")
                .payload(Map.of("data", largeString))
                .build();

        assertThrows(IllegalArgumentException.class, () -> auditLogService.createEvent(req),
                "Oversized payload exceeding 256KB limit must be rejected");
    }

    @Test
    @WithMockUser(username = "ingest_user", roles = {"INGEST"})
    @DisplayName("Phase 6: Deeply nested JSON (>15 levels) throws IllegalArgumentException")
    void testDeeplyNestedJsonRejected() {
        Map<String, Object> deepMap = new HashMap<>();
        Map<String, Object> current = deepMap;
        for (int i = 0; i < 20; i++) {
            Map<String, Object> child = new HashMap<>();
            current.put("level" + i, child);
            current = child;
        }

        CreateEventRequest req = CreateEventRequest.builder()
                .eventType("NESTED_EVENT")
                .actorId("ingest_user")
                .resourceType("DOC")
                .resourceId("DOC-1")
                .payload(deepMap)
                .build();

        assertThrows(IllegalArgumentException.class, () -> auditLogService.createEvent(req),
                "Deeply nested JSON exceeding 15 levels must be rejected");
    }

    @Test
    @WithMockUser(username = "ingest_user", roles = {"INGEST"})
    @DisplayName("Phase 6: Normal request within limits succeeds cleanly")
    void testNormalRequestWithinLimitsSucceeds() {
        CreateEventRequest req = CreateEventRequest.builder()
                .eventType("VALID_EVENT")
                .actorId("ingest_user")
                .resourceType("ITEM")
                .resourceId("ITEM-123")
                .payload(Map.of("status", "ACTIVE", "code", 200))
                .build();

        AuditRecord record = auditLogService.createEvent(req);
        assertNotNull(record.getId());
        assertEquals("VALID_EVENT", record.getEventType());
    }
}
