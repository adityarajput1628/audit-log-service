package com.schwab.auditlog.config;

import com.schwab.auditlog.crypto.HashChainEngine;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MissingSecretConfigurationTest {

    @Test
    @DisplayName("SEC-01: Missing HMAC secret configuration throws IllegalArgumentException without silent fallback")
    void testMissingSecretThrowsExceptionWithoutFallback() {
        assertThatThrownBy(() -> new HashChainEngine(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("HMAC secret configuration")
                .hasMessageContaining("is required and cannot be blank");

        assertThatThrownBy(() -> new HashChainEngine("   "))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("HMAC secret configuration")
                .hasMessageContaining("is required and cannot be blank");
    }
}
