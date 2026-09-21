package com.schwab.auditlog.service;

import com.schwab.auditlog.dto.CreateEventRequest;
import com.schwab.auditlog.model.AuditRecord;
import com.schwab.auditlog.repository.AuditRecordRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Page;
import org.springframework.test.annotation.DirtiesContext;

import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
class ValidationAndEdgeCaseTest {

    @Autowired
    private AuditLogService auditLogService;

    @Autowired
    private ExportService exportService;

    @Autowired
    private AuditRecordRepository repository;

    @BeforeEach
    void setUp() {
        repository.deleteAll();
    }

    @Test
    @DisplayName("Invalid date range 'from' after 'to' throws IllegalArgumentException")
    void testInvalidDateRangeThrowsException() {
        Instant now = Instant.now();
        Instant future = now.plusSeconds(3600);

        assertThatThrownBy(() -> auditLogService.queryEvents(null, null, null, null, future, now, false, 0, 10))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("'from' timestamp cannot be after 'to' timestamp.");
    }

    @Test
    @DisplayName("Pagination bounds page size to max 100")
    void testPageSizeBounds() {
        CreateEventRequest req = CreateEventRequest.builder()
                .eventType("EVENT")
                .actorId("actor")
                .resourceType("RES")
                .resourceId("ID-1")
                .payload(Map.of("data", "test"))
                .build();

        auditLogService.createEvent(req);

        Page<AuditRecord> page = auditLogService.queryEvents(null, null, null, null, null, null, false, 0, 1000);
        assertThat(page.getSize()).isEqualTo(100);
    }

    @Test
    @DisplayName("Export request without resourceId or actorId throws IllegalArgumentException")
    void testExportWithoutFilterThrowsException() {
        assertThatThrownBy(() -> exportService.generateExportBundle(null, " "))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Must specify either resourceId or actorId for export.");
    }

    @Test
    @DisplayName("Null create event request throws IllegalArgumentException")
    void testNullCreateEventRequestThrowsException() {
        assertThatThrownBy(() -> auditLogService.createEvent(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("CreateEventRequest cannot be null.");
    }
}
