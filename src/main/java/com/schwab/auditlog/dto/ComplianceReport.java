package com.schwab.auditlog.dto;

import lombok.*;

import java.time.Instant;
import java.util.List;
import java.util.Map;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ComplianceReport {

    private String reportId;
    private String title;
    private Instant generatedAt;
    private String clientAccountId;
    private Instant fromTimestamp;
    private Instant toTimestamp;
    private long totalAccessEvents;
    private long uniqueActors;
    private List<ActorAccessSummary> actorSummaries;
    private List<Map<String, Object>> accessLogTrail;
    private VerificationResult chainVerification;
    private String cryptographicProofToken;

    @Getter
    @Setter
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class ActorAccessSummary {
        private String actorId;
        private long accessCount;
        private Instant firstAccess;
        private Instant lastAccess;
        private List<String> eventTypes;
    }
}
