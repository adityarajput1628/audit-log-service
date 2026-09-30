package com.schwab.auditlog.service;

import com.schwab.auditlog.model.ChainCheckpoint;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CheckpointSchedulerTest {

    @Mock
    private AuditLogService auditLogService;

    @InjectMocks
    private CheckpointScheduler checkpointScheduler;

    @Test
    @DisplayName("Automated Checkpoint publishing runs successfully when enabled")
    void testPublishAutomatedCheckpointEnabled() {
        ReflectionTestUtils.setField(checkpointScheduler, "checkpointEnabled", true);

        ChainCheckpoint dummyCheckpoint = ChainCheckpoint.builder()
                .checkpointId("chk-auto-100")
                .headSequenceNumber(10L)
                .headRecordHash("hash100")
                .checkpointTimestamp(Instant.now())
                .checkpointVersion("v1")
                .signature("sig100")
                .build();

        when(auditLogService.createCheckpoint()).thenReturn(dummyCheckpoint);

        checkpointScheduler.publishAutomatedCheckpoint();

        verify(auditLogService, times(1)).createCheckpoint();
    }

    @Test
    @DisplayName("Automated Checkpoint publishing skips when disabled by config")
    void testPublishAutomatedCheckpointDisabled() {
        ReflectionTestUtils.setField(checkpointScheduler, "checkpointEnabled", false);

        checkpointScheduler.publishAutomatedCheckpoint();

        verify(auditLogService, never()).createCheckpoint();
    }

    @Test
    @DisplayName("Automated Checkpoint handles service exceptions gracefully without crashing")
    void testPublishAutomatedCheckpointExceptionHandling() {
        ReflectionTestUtils.setField(checkpointScheduler, "checkpointEnabled", true);
        when(auditLogService.createCheckpoint()).thenThrow(new RuntimeException("Database timeout simulation"));

        checkpointScheduler.publishAutomatedCheckpoint();

        verify(auditLogService, times(1)).createCheckpoint();
    }
}
