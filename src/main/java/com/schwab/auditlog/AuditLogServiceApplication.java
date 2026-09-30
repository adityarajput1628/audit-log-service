package com.schwab.auditlog;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class AuditLogServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuditLogServiceApplication.class, args);
    }
}

