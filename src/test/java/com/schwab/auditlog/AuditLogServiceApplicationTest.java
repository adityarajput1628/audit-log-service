package com.schwab.auditlog;

import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ConfigurableApplicationContext;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;

class AuditLogServiceApplicationTest {

    @Test
    void mainMethodInvokesSpringApplicationRun() {
        try (MockedStatic<SpringApplication> mocked = mockStatic(SpringApplication.class)) {
            ConfigurableApplicationContext mockContext = mock(ConfigurableApplicationContext.class);
            mocked.when(() -> SpringApplication.run(eq(AuditLogServiceApplication.class), any(String[].class)))
                    .thenReturn(mockContext);

            AuditLogServiceApplication.main(new String[]{});

            mocked.verify(() -> SpringApplication.run(eq(AuditLogServiceApplication.class), any(String[].class)), times(1));
        }
    }
}
