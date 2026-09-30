package com.schwab.auditlog.config;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

import java.util.Arrays;

/**
 * Production TLS Configuration & Enforcement Component.
 * Ensures that starting the application in the 'prod' profile without active SSL
 * or an explicit trusted proxy TLS termination override fails fast during startup.
 */
@Configuration
public class TlsEnforcementConfig {

    private final Environment environment;
    private final boolean sslEnabled;
    private final boolean trustedProxyOverride;

    public TlsEnforcementConfig(
            Environment environment,
            @Value("${server.ssl.enabled:false}") boolean sslEnabled,
            @Value("${schwab.security.tls.trusted-proxy-override:false}") boolean trustedProxyOverride
    ) {
        this.environment = environment;
        this.sslEnabled = sslEnabled;
        this.trustedProxyOverride = trustedProxyOverride;
    }

    @PostConstruct
    public void validateTlsConfiguration() {
        boolean isProdProfile = Arrays.asList(environment.getActiveProfiles()).contains("prod");
        if (isProdProfile && !sslEnabled && !trustedProxyOverride) {
            throw new IllegalStateException(
                "Production security violation: TLS (server.ssl.enabled) must be enabled in 'prod' profile " +
                "unless trusted proxy TLS termination (TRUSTED_PROXY_TLS_TERMINATION=true) is explicitly configured."
            );
        }
    }
}
