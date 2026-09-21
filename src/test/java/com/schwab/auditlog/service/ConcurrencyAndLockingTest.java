package com.schwab.auditlog.service;

import com.schwab.auditlog.dto.CreateEventRequest;
import com.schwab.auditlog.dto.VerificationResult;
import com.schwab.auditlog.model.AuditRecord;
import com.schwab.auditlog.repository.AuditRecordRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
class ConcurrencyAndLockingTest {

    @Autowired
    private AuditLogService auditLogService;

    @Autowired
    private AuditRecordRepository repository;

    @BeforeEach
    void setUp() {
        repository.deleteAll();
    }

    @Test
    @DisplayName("Concurrent event ingestions produce strict monotonic non-overlapping sequence numbers")
    void testConcurrentIngestionProducesSequentialNonOverlappingIds() throws InterruptedException {
        int threadCount = 10;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(threadCount);

        List<AuditRecord> createdRecords = Collections.synchronizedList(new ArrayList<>());

        for (int i = 0; i < threadCount; i++) {
            final int index = i;
            executor.submit(() -> {
                try {
                    startLatch.await();
                    CreateEventRequest req = CreateEventRequest.builder()
                            .eventType("CONCURRENT_EVENT")
                            .actorId("actor-" + index)
                            .resourceType("THREAD")
                            .resourceId("RES-" + index)
                            .payload(Map.of("threadIndex", index))
                            .build();

                    AuditRecord record = auditLogService.createEvent(req);
                    createdRecords.add(record);
                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        startLatch.countDown(); // Trigger all threads simultaneously
        doneLatch.await();
        executor.shutdown();

        assertThat(createdRecords).hasSize(threadCount);

        List<AuditRecord> allInDb = repository.findAllByOrderBySequenceNumberAsc();
        assertThat(allInDb).hasSize(threadCount);

        // Verify sequence numbers 1..10 exist without gaps or duplicates
        for (int i = 0; i < threadCount; i++) {
            assertThat(allInDb.get(i).getSequenceNumber()).isEqualTo((long) (i + 1));
        }

        // Verify cryptographic hash chain continuity across concurrent writes
        VerificationResult verification = auditLogService.verifyChain();
        assertThat(verification.isIntact()).isTrue();
        assertThat(verification.getTotalRecordsChecked()).isEqualTo(threadCount);
    }
}
