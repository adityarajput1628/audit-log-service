package com.schwab.auditlog.service;

import com.schwab.auditlog.AuditLogServiceApplication;
import com.schwab.auditlog.dto.CreateEventRequest;
import com.schwab.auditlog.dto.VerificationResult;
import com.schwab.auditlog.model.AuditRecord;
import com.schwab.auditlog.repository.AuditRecordRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

public class MultiInstanceContextSimulationTest {

    @Test
    @DisplayName("ARCH-04: Multi-instance context simulation - Two independent Spring Application Contexts writing to shared database")
    void testTwoIndependentSpringContextsWritingConcurrently() throws InterruptedException {
        String runtimeHmacSecret = "test-secret-" + UUID.randomUUID().toString();
        String runtimeIngestPass = "ingest-" + UUID.randomUUID().toString();
        String runtimeAuditorPass = "auditor-" + UUID.randomUUID().toString();
        String runtimeAdminPass = "admin-" + UUID.randomUUID().toString();

        // Start Instance 1 with random port
        ConfigurableApplicationContext node1Context = new SpringApplicationBuilder(AuditLogServiceApplication.class)
                .properties(
                        "spring.profiles.active=test",
                        "server.port=0",
                        "spring.datasource.url=jdbc:h2:mem:multinodedb;DB_CLOSE_DELAY=-1;MODE=PostgreSQL",
                        "schwab.security.users.ingest.username=test_ingest_user",
                        "schwab.security.users.ingest.password=" + runtimeIngestPass,
                        "schwab.security.users.auditor.username=test_auditor_user",
                        "schwab.security.users.auditor.password=" + runtimeAuditorPass,
                        "schwab.security.users.admin.username=test_admin_user",
                        "schwab.security.users.admin.password=" + runtimeAdminPass,
                        "schwab.security.hmac.secret=" + runtimeHmacSecret
                )
                .run();

        // Start Instance 2 sharing the same database URL with random port
        ConfigurableApplicationContext node2Context = new SpringApplicationBuilder(AuditLogServiceApplication.class)
                .properties(
                        "spring.profiles.active=test",
                        "server.port=0",
                        "spring.datasource.url=jdbc:h2:mem:multinodedb;DB_CLOSE_DELAY=-1;MODE=PostgreSQL",
                        "schwab.security.users.ingest.username=test_ingest_user",
                        "schwab.security.users.ingest.password=" + runtimeIngestPass,
                        "schwab.security.users.auditor.username=test_auditor_user",
                        "schwab.security.users.auditor.password=" + runtimeAuditorPass,
                        "schwab.security.users.admin.username=test_admin_user",
                        "schwab.security.users.admin.password=" + runtimeAdminPass,
                        "schwab.security.hmac.secret=" + runtimeHmacSecret
                )
                .run();

        try {
            AuditLogService node1Service = node1Context.getBean(AuditLogService.class);
            AuditLogService node2Service = node2Context.getBean(AuditLogService.class);
            AuditRecordRepository repo = node1Context.getBean(AuditRecordRepository.class);

            repo.deleteAll();

            int eventsPerNode = 10;
            int totalEvents = eventsPerNode * 2;
            ExecutorService executor = Executors.newFixedThreadPool(totalEvents);
            CountDownLatch startLatch = new CountDownLatch(1);
            CountDownLatch doneLatch = new CountDownLatch(totalEvents);

            List<AuditRecord> results = Collections.synchronizedList(new ArrayList<>());

            for (int i = 0; i < eventsPerNode; i++) {
                final int idx = i;
                executor.submit(() -> {
                    try {
                        startLatch.await();
                        AuditRecord record = createEventWithRetry(node1Service, CreateEventRequest.builder()
                                .eventType("NODE_1_EVENT")
                                .actorId("node1-actor")
                                .resourceType("CLUSTER")
                                .resourceId("RES-1-" + idx)
                                .payload(Map.of("index", idx))
                                .build());
                        results.add(record);
                    } catch (Exception e) {
                        e.printStackTrace();
                    } finally {
                        doneLatch.countDown();
                    }
                });

                executor.submit(() -> {
                    try {
                        startLatch.await();
                        AuditRecord record = createEventWithRetry(node2Service, CreateEventRequest.builder()
                                .eventType("NODE_2_EVENT")
                                .actorId("node2-actor")
                                .resourceType("CLUSTER")
                                .resourceId("RES-2-" + idx)
                                .payload(Map.of("index", idx))
                                .build());
                        results.add(record);
                    } catch (Exception e) {
                        e.printStackTrace();
                    } finally {
                        doneLatch.countDown();
                    }
                });
            }

            startLatch.countDown();
            doneLatch.await();
            executor.shutdown();

            assertThat(results).hasSize(totalEvents);

            List<AuditRecord> allInDb = repo.findAllByOrderBySequenceNumberAsc();
            assertThat(allInDb).hasSize(totalEvents);

            for (int i = 0; i < totalEvents; i++) {
                assertThat(allInDb.get(i).getSequenceNumber()).isEqualTo((long) (i + 1));
            }

            VerificationResult verification = node1Service.verifyChain();
            assertThat(verification.isIntact()).isTrue();
        } finally {
            node1Context.close();
            node2Context.close();
        }
    }

    private AuditRecord createEventWithRetry(AuditLogService service, CreateEventRequest request) throws Exception {
        int retries = 5;
        for (int attempt = 0; attempt < retries; attempt++) {
            try {
                return service.createEvent(request);
            } catch (Exception e) {
                if (attempt == retries - 1) throw e;
                Thread.sleep(50 + (long) (Math.random() * 50));
            }
        }
        return service.createEvent(request);
    }
}
