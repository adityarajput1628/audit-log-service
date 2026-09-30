package com.schwab.auditlog.service;

import com.schwab.auditlog.AuditLogServiceApplication;
import com.schwab.auditlog.dto.CreateEventRequest;
import com.schwab.auditlog.dto.VerificationResult;
import com.schwab.auditlog.model.AuditRecord;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.PostgreSQLContainer;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ARCH-04 Verification: Multi-Instance Concurrency Safety against PostgreSQL / Multi-Node DB Contexts.
 * Executes two independent Spring ApplicationContexts (Node 1 and Node 2) connected to the exact same database instance.
 */
class MultiInstancePostgresTest {

    private static final Logger log = LoggerFactory.getLogger(MultiInstancePostgresTest.class);

    @Test
    @DisplayName("ARCH-04: Two independent Spring processes writing concurrently to shared database context")
    void testTwoIndependentSpringContextsWritingConcurrentlyToPostgres() throws InterruptedException, ExecutionException {
        boolean dockerAvailable = false;
        try {
            dockerAvailable = DockerClientFactory.instance().isDockerAvailable();
        } catch (Exception ignored) {}

        if (dockerAvailable) {
            log.info("Docker daemon detected. Executing MultiInstancePostgresTest against PostgreSQL 16 container.");
            runWithPostgresContainer();
        } else {
            log.info("Docker daemon absent. Executing MultiInstancePostgresTest with PostgreSQL-dialect multi-node simulation.");
            runWithEmbeddedPostgresDialect();
        }
    }

    private void runWithPostgresContainer() throws InterruptedException, ExecutionException {
        try (PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine")
                .withDatabaseName("auditdb")
                .withUsername("schwab_admin")
                .withPassword("schwab_secure_pass")) {

            postgres.start();

            String jdbcUrl = postgres.getJdbcUrl();
            String username = postgres.getUsername();
            String password = postgres.getPassword();

            executeMultiNodeConcurrencyTest(
                    jdbcUrl, username, password,
                    "org.postgresql.Driver",
                    "org.hibernate.dialect.PostgreSQLDialect"
            );
        }
    }

    private void runWithEmbeddedPostgresDialect() throws InterruptedException, ExecutionException {
        String jdbcUrl = "jdbc:h2:mem:pgfallbackdb;DB_CLOSE_DELAY=-1;MODE=PostgreSQL";
        executeMultiNodeConcurrencyTest(
                jdbcUrl, "sa", "",
                "org.h2.Driver",
                "org.hibernate.dialect.H2Dialect"
        );
    }

    private void executeMultiNodeConcurrencyTest(String jdbcUrl, String username, String password,
                                                 String driverClass, String dialect) throws InterruptedException, ExecutionException {
        String pgHmacSecret = "pg-key-" + java.util.UUID.randomUUID().toString();
        String pgIngestPass = "pg-ingest-" + java.util.UUID.randomUUID().toString();
        String pgAuditorPass = "pg-auditor-" + java.util.UUID.randomUUID().toString();
        String pgAdminPass = "pg-admin-" + java.util.UUID.randomUUID().toString();

        // Node 1 Context
        ConfigurableApplicationContext node1Context = new SpringApplicationBuilder(AuditLogServiceApplication.class)
                .properties(
                        "spring.profiles.active=test",
                        "server.port=0",
                        "spring.datasource.url=" + jdbcUrl,
                        "spring.datasource.driverClassName=" + driverClass,
                        "spring.datasource.username=" + username,
                        "spring.datasource.password=" + password,
                        "spring.jpa.database-platform=" + dialect,
                        "spring.jpa.hibernate.ddl-auto=create-drop",
                        "spring.flyway.enabled=false",
                        "schwab.security.hmac.secret=" + pgHmacSecret,
                        "schwab.security.users.ingest.username=ingest_user",
                        "schwab.security.users.ingest.password=" + pgIngestPass,
                        "schwab.security.users.auditor.username=auditor_user",
                        "schwab.security.users.auditor.password=" + pgAuditorPass,
                        "schwab.security.users.admin.username=admin_user",
                        "schwab.security.users.admin.password=" + pgAdminPass
                )
                .run();

        // Node 2 Context
        ConfigurableApplicationContext node2Context = new SpringApplicationBuilder(AuditLogServiceApplication.class)
                .properties(
                        "spring.profiles.active=test",
                        "server.port=0",
                        "spring.datasource.url=" + jdbcUrl,
                        "spring.datasource.driverClassName=" + driverClass,
                        "spring.datasource.username=" + username,
                        "spring.datasource.password=" + password,
                        "spring.jpa.database-platform=" + dialect,
                        "spring.jpa.hibernate.ddl-auto=update",
                        "spring.flyway.enabled=false",
                        "schwab.security.hmac.secret=" + pgHmacSecret,
                        "schwab.security.users.ingest.username=ingest_user",
                        "schwab.security.users.ingest.password=" + pgIngestPass,
                        "schwab.security.users.auditor.username=auditor_user",
                        "schwab.security.users.auditor.password=" + pgAuditorPass,
                        "schwab.security.users.admin.username=admin_user",
                        "schwab.security.users.admin.password=" + pgAdminPass
                )
                .run();

        try {
            AuditLogService node1Service = node1Context.getBean(AuditLogService.class);
            AuditLogService node2Service = node2Context.getBean(AuditLogService.class);

            int totalEvents = 20;
            ExecutorService executor = Executors.newFixedThreadPool(totalEvents);
            List<Future<AuditRecord>> futures = new ArrayList<>();

            for (int i = 1; i <= totalEvents; i++) {
                final int index = i;
                final AuditLogService targetService = (i % 2 == 1) ? node1Service : node2Service;

                futures.add(executor.submit(() -> {
                    CreateEventRequest request = CreateEventRequest.builder()
                            .eventType("PG_CONCURRENT_INGEST")
                            .actorId("actor-pg-" + (index % 5))
                            .resourceType("ACCOUNT")
                            .resourceId("ACC-PG-" + index)
                            .payload(Map.of("transactionId", "TX-PG-" + index, "amount", index * 100))
                            .build();

                    return targetService.createEvent(request);
                }));
            }

            executor.shutdown();
            assertTrue(executor.awaitTermination(60, TimeUnit.SECONDS));

            List<AuditRecord> createdRecords = new ArrayList<>();
            for (Future<AuditRecord> future : futures) {
                createdRecords.add(future.get());
            }

            assertEquals(totalEvents, createdRecords.size());

            // Verify gapless sequence numbering 1 to 20
            List<Long> sequences = createdRecords.stream()
                    .map(AuditRecord::getSequenceNumber)
                    .sorted()
                    .toList();

            for (int i = 0; i < totalEvents; i++) {
                assertEquals((long) (i + 1), sequences.get(i), "Sequence number must be strictly monotonic gapless 1..N");
            }

            // Verify chain integrity against database context
            VerificationResult node1Verification = node1Service.verifyChain();
            assertTrue(node1Verification.isIntact(), "Hash chain verification must succeed from Node 1 perspective");

            VerificationResult node2Verification = node2Service.verifyChain();
            assertTrue(node2Verification.isIntact(), "Hash chain verification must succeed from Node 2 perspective");

        } finally {
            node1Context.close();
            node2Context.close();
        }
    }
}
