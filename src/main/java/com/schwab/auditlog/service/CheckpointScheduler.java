package com.schwab.auditlog.service;

import com.schwab.auditlog.model.ChainCheckpoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Automated External Checkpoint Publishing Scheduler.
 * Periodically generates signed HMAC cryptographic chain head checkpoints
 * and anchors them to external log targets without manual intervention.
 */
@Component
public class CheckpointScheduler {

    private static final Logger log = LoggerFactory.getLogger(CheckpointScheduler.class);

    private final AuditLogService auditLogService;

    @Value("${schwab.audit.checkpoint.enabled:true}")
    private boolean checkpointEnabled;

    public CheckpointScheduler(AuditLogService auditLogService) {
        this.auditLogService = auditLogService;
    }

    /**
     * Automated checkpoint task running every 5 minutes by default (configurable via schwab.audit.checkpoint.cron).
     */
    @Scheduled(cron = "${schwab.audit.checkpoint.cron:0 */5 * * * *}")
    public void publishAutomatedCheckpoint() {
        if (!checkpointEnabled) {
            log.info("Automated checkpoint publishing is currently disabled via configuration.");
            return;
        }

        try {
            ChainCheckpoint checkpoint = auditLogService.createCheckpoint();
            log.info("AUTOMATED CHECKPOINT PUBLISHED: ID={}, HeadSeq={}, HeadHash={}",
                    checkpoint.getCheckpointId(),
                    checkpoint.getHeadSequenceNumber(),
                    checkpoint.getHeadRecordHash());
        } catch (Exception e) {
            log.error("Failed to publish automated external checkpoint: {}", e.getMessage(), e);
        }
    }
}
