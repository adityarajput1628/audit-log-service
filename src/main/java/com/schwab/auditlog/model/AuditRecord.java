package com.schwab.auditlog.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(name = "audit_records", indexes = {
    @Index(name = "idx_sequence", columnList = "sequenceNumber", unique = true),
    @Index(name = "idx_actor", columnList = "actorId"),
    @Index(name = "idx_resource", columnList = "resourceType, resourceId"),
    @Index(name = "idx_event_type", columnList = "eventType"),
    @Index(name = "idx_timestamp", columnList = "timestamp")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuditRecord {

    public static final String GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private Long sequenceNumber;

    @Column(nullable = false)
    private String eventType;

    @Column(nullable = false)
    private String actorId;

    @Column(nullable = false)
    private String resourceType;

    @Column(nullable = false)
    private String resourceId;

    @Column(columnDefinition = "TEXT")
    private String payloadJson;

    @Column(columnDefinition = "TEXT")
    private String redactionsJson;

    @Column(nullable = false)
    private Instant timestamp;

    @Column(nullable = false, length = 64)
    private String previousHash;

    @Column(nullable = false, length = 64)
    private String recordHash;

    @Column(nullable = false)
    @Builder.Default
    private boolean archived = false;

    private Instant archivedAt;
}
