package com.schwab.auditlog.dto;

import lombok.*;

import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VerificationResult {

    private boolean intact;
    private long totalRecordsChecked;
    private long activeRecordsChecked;
    private long archivedRecordsChecked;
    private String statusMessage;
    
    @Builder.Default
    private List<ViolationDetail> violations = new ArrayList<>();

    @Getter
    @Setter
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class ViolationDetail {
        private Long sequenceNumber;
        private Long recordId;
        private String violationType; // HASH_MISMATCH, PREVIOUS_HASH_MISMATCH, SEQUENCE_GAP, TIMESTAMP_ANOMALY
        private String expectedHash;
        private String actualHash;
        private String description;
    }
}
