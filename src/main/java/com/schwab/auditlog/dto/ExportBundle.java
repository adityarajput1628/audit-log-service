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
public class ExportBundle {

    private String exportId;
    private Instant exportedAt;
    private String filterType; // "resourceId" or "actorId"
    private String filterValue;
    private long recordCount;
    private List<Map<String, Object>> records;
    private String exportDigest; // SHA-256 digest of exported records payload
    private String chainGenesisHash;
    private String chainLatestHash;
    private String verificationStatus; // "VERIFIED_INTACT"
}
