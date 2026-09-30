package com.schwab.auditlog.config;

import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

import static org.junit.jupiter.api.Assertions.*;

class TlsEnforcementTest {

    @Test
    void testProdProfileWithoutTlsOrProxyOverrideFailsFast() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("prod");

        TlsEnforcementConfig config = new TlsEnforcementConfig(env, false, false);

        IllegalStateException ex = assertThrows(IllegalStateException.class, config::validateTlsConfiguration);
        assertTrue(ex.getMessage().contains("Production security violation: TLS"),
                "Error message must explicitly cite TLS requirement in prod profile");
    }

    @Test
    void testProdProfileWithTrustedProxyOverridePassesValidation() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("prod");

        TlsEnforcementConfig config = new TlsEnforcementConfig(env, false, true);
        // Should not throw exception when trusted proxy override is enabled
        assertDoesNotThrow(config::validateTlsConfiguration);
    }

    @Test
    void testDevProfileWithoutTlsPassesValidation() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("dev");

        TlsEnforcementConfig config = new TlsEnforcementConfig(env, false, false);
        // Should not throw exception in dev profile
        assertDoesNotThrow(config::validateTlsConfiguration);
    }
}
