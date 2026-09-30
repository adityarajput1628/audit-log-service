# System Architecture & Technical Design Document

## 1. Core Design Objectives
The **Audit Log Service** is designed to provide an immutable, tamper-evident record of security and business operations for Charles Schwab enterprise systems.

### Key Architectural Tenets
1. **Append-Only Ingestion**: Data modification or deletion APIs are strictly excluded from domain model and HTTP endpoints. Retention appends `RETENTION_TOMBSTONE` records without altering historical hashes.
2. **Cryptographic Continuity & External Checkpoints**: Every record is linked to its predecessor via SHA-256 digests. Modifying any past record breaks its hash and invalidates all downstream hashes. External periodic checkpoints (`chain_checkpoints`) provide out-of-band Merkle/chain validation.
3. **Actor Provenance & Impersonation Guardrail**: Ingestion strictly binds `actorId` to `SecurityContextHolder` authenticated principal, preventing identity spoofing.
4. **Authoritative Ingestion Timestamping**: Server generates ISO-8601 UTC ingestion timestamp while preserving client-provided occurrence time as `_occurredAt`.
5. **Idempotency & Replay Protection**: DB-backed `Idempotency-Key` tracking preventing duplicate event ingestion.
6. **Data Privacy vs Tamper Evidence**: Implements zero-knowledge salted field redaction, enabling GDPR/CCPA PII removal without invalidating cryptographic hash chain proofs.
7. **Flyway Managed Migrations**: DDL schema management with `V1__init_schema.sql` and `V2__add_checkpoints_and_idempotency.sql`.

---

## 2. Cryptographic Hash Engine Design

### Algorithm Choice
- **SHA-256**: Selected for standard enterprise compliance, hardware acceleration, zero collisions in practical audit volume, and standard Java `java.security.MessageDigest` availability.

### Canonical Serialization
To guarantee deterministic hashing across heterogeneous environments:
- JSON key sorting enabled via Jackson `MapperFeature.SORT_PROPERTIES_ALPHABETICALLY`.
- ISO-8601 UTC Instant timestamp string formatting (`Instant.ofEpochMilli(timestamp.toEpochMilli()).toString()`).
- Explicit pipe (`|`) delimiter separation between fields.

---

## 3. Data Model & Schema Definition (Flyway Managed)

```sql
-- V1__init_schema.sql
CREATE TABLE audit_records (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    sequence_number BIGINT NOT NULL UNIQUE,
    event_type VARCHAR(255) NOT NULL,
    actor_id VARCHAR(255) NOT NULL,
    resource_type VARCHAR(255) NOT NULL,
    resource_id VARCHAR(255) NOT NULL,
    payload_json TEXT,
    redactions_json TEXT,
    timestamp TIMESTAMP NOT NULL,
    previous_hash VARCHAR(64) NOT NULL,
    record_hash VARCHAR(64) NOT NULL,
    archived BOOLEAN NOT NULL DEFAULT FALSE,
    archived_at TIMESTAMP
);

CREATE INDEX idx_sequence ON audit_records(sequence_number);
CREATE INDEX idx_actor ON audit_records(actor_id);
CREATE INDEX idx_resource ON audit_records(resource_type, resource_id);
CREATE INDEX idx_timestamp ON audit_records(timestamp);

-- V2__add_checkpoints_and_idempotency.sql
CREATE TABLE chain_checkpoints (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    checkpoint_id VARCHAR(255) NOT NULL UNIQUE,
    created_at TIMESTAMP NOT NULL,
    start_sequence BIGINT NOT NULL,
    end_sequence BIGINT NOT NULL,
    record_count BIGINT NOT NULL,
    checkpoint_hash VARCHAR(64) NOT NULL,
    previous_checkpoint_hash VARCHAR(64)
);

CREATE TABLE idempotency_records (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    idempotency_key VARCHAR(255) NOT NULL UNIQUE,
    payload_hash VARCHAR(64) NOT NULL,
    created_at TIMESTAMP NOT NULL,
    audit_record_id BIGINT NOT NULL
);
```

---

## 4. Verification & Defense Mechanism
The `verifyChain()` routine walks records ordered by `sequence_number ASC`:
1. Validates `sequence_number` starts at 1 and increases monotonically without gaps.
2. Validates record #1 `previous_hash` equals Genesis Zero Hash (`0000...0000`).
3. Validates record $N$ `previous_hash` equals record $N-1$ `record_hash`.
4. Recomputes record $N$ `record_hash` and asserts equality with stored `record_hash`.
5. Reports pinpointed violation details (`HASH_MISMATCH`, `PREVIOUS_HASH_MISMATCH`, `SEQUENCE_GAP`) upon detecting direct database tampering.
