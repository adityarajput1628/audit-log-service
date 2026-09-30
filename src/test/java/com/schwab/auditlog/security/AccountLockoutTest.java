package com.schwab.auditlog.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AccountLockoutTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AccountLockoutService lockoutService;

    @org.springframework.beans.factory.annotation.Value("${schwab.security.users.ingest.username}")
    private String ingestUser;

    @org.springframework.beans.factory.annotation.Value("${schwab.security.users.ingest.password}")
    private String ingestPass;

    @org.springframework.beans.factory.annotation.Value("${schwab.security.users.auditor.username}")
    private String auditorUser;

    @org.springframework.beans.factory.annotation.Value("${schwab.security.users.auditor.password}")
    private String auditorPass;

    @BeforeEach
    void setUp() {
        lockoutService.resetLockout(ingestUser);
        lockoutService.resetLockout(auditorUser);
    }

    @Test
    void testFiveFailedAttemptsLocksAccountAndDifferentUserUnaffected() throws Exception {
        // 1. Make 5 wrong-password attempts for ingestUser
        for (int i = 0; i < 5; i++) {
            mockMvc.perform(get("/api/v1/audit/events")
                    .with(httpBasic(ingestUser, "wrong_password_" + i)))
                    .andExpect(status().isUnauthorized()); // 401
        }

        // 2. 6th attempt with CORRECT password for ingestUser returns 423 Locked
        mockMvc.perform(get("/api/v1/audit/events")
                .with(httpBasic(ingestUser, ingestPass)))
                .andExpect(status().isLocked()); // 423

        // 3. Different user (auditorUser) with correct password is unaffected and succeeds (200)
        mockMvc.perform(get("/api/v1/audit/events")
                .with(httpBasic(auditorUser, auditorPass)))
                .andExpect(status().isOk()); // 200
    }
}
