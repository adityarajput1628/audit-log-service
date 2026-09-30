package com.schwab.auditlog.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(name = "chain_checkpoints", indexes = {
    @Index(name = "idx_checkpoint_seq", columnList = "headSequenceNumber"),
    @Index(name = "idx_checkpoint_time", columnList = "checkpointTimestamp")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ChainCheckpoint {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String checkpointId;

    @Column(nullable = false)
    private Long headSequenceNumber;

    @Column(nullable = false, length = 64)
    private String headRecordHash;

    @Column(nullable = false)
    private Instant checkpointTimestamp;

    @Column(nullable = false, length = 50)
    private String checkpointVersion;

    @Column(nullable = false, length = 512)
    private String signature;

    @Column(nullable = false, length = 50)
    @Builder.Default
    private String status = "VALID";
}
