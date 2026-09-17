package com.schwab.auditlog.crypto;

import com.schwab.auditlog.model.AuditRecord;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class HashChainEngineTest {

    private HashChainEngine hashChainEngine;

    @BeforeEach
    void setUp() {
        hashChainEngine = new HashChainEngine();
    }

    @Test
    @DisplayName("SHA-256 hex string should be 64 characters long and deterministic")
    void testSha256Hex() {
        String hash1 = hashChainEngine.sha256Hex("hello-schwab");
        String hash2 = hashChainEngine.sha256Hex("hello-schwab");

        assertThat(hash1).hasSize(64);
        assertThat(hash1).isEqualTo(hash2);
    }

    @Test
    @DisplayName("Record hash calculation should be reproducible")
    void testCalculateRecordHash() {
        Instant timestamp = Instant.parse("2026-09-17T10:00:00Z");
        AuditRecord record = AuditRecord.builder()
                .sequenceNumber(1L)
                .eventType("USER_LOGIN")
                .actorId("user-123")
                .resourceType("SYSTEM")
                .resourceId("AUTH")
                .payloadJson("{\"ip\":\"127.0.0.1\"}")
                .redactionsJson("{}")
                .timestamp(timestamp)
                .previousHash(AuditRecord.GENESIS_HASH)
                .build();

        String hash1 = hashChainEngine.calculateRecordHash(record);
        String hash2 = hashChainEngine.calculateRecordHash(record);

        assertThat(hash1).hasSize(64);
        assertThat(hash1).isEqualTo(hash2);
    }
}
