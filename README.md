# AI-Assisted Software Engineering System – Audit Log Service
**Charles Schwab & Co., Inc. – Confidential & Proprietary (Version 2.0)**

---

## Executive Summary

This repository contains a production-grade, tamper-evident **Audit Log Service** engineered using **Java 17**, **Spring Boot 3.3**, **Flyway**, and **Gradle**. 

The system guarantees:
- **P0 Security Boundary & RBAC Authorization**: Enforces Spring Security HTTP Basic authentication with Role-Based Access Control (`ROLE_INGEST`, `ROLE_AUDITOR`, `ROLE_ADMIN`), explicit CORS origins, HSTS security headers, and isolated sensitive operations.
- **Append-Only Immutability & Retention**: No update or delete operations on audit records. Policy-based retention archives records while appending verifiable `RETENTION_TOMBSTONE` events without mutating historical hashes.
- **Cryptographic Tamper Evidence & Checkpointing**: Sequential SHA-256 hash chaining linking every event to the prior record's digest back to a defined Genesis Zero hash, supplemented by periodic external chain checkpoints (`POST /checkpoint`, `GET /checkpoint/{id}/verify`).
- **Actor Provenance & Impersonation Guardrails**: Ingestion binds `actorId` to `SecurityContextHolder` authenticated principal, preventing identity spoofing while allowing authorized delegation.
- **Authoritative Ingestion Timestamping**: Server generates ISO-8601 UTC ingestion timestamp while preserving client-provided occurrence time as `_occurredAt`.
- **Idempotency & Replay Protection**: DB-backed `Idempotency-Key` tracking preventing duplicate event ingestion.
- **Input Controls & Rate Limiting**: Payload size limits (256KB), JSON nesting depth verification (max 15 levels), and token bucket HTTP rate limiting (`429 Too Many Requests`).
- **Database Schema Management**: Managed DDL transitions via Flyway migrations (`V1__init_schema.sql`, `V2__add_checkpoints_and_idempotency.sql`).
- **Archived Record Integrity Verification**: Cryptographically verifies **ALL** records (active AND archived tombstones) in `verifyChain()`, catching direct database tampering on archived tombstones or metadata.
- **Zero-Knowledge Field Redaction (Scenario B)**: Masks sensitive PII (account numbers, SSNs) to `"[REDACTED]"` while preserving 100% cryptographic hash chain validity using salted field digests.
- **Keyed HMAC Proof Bundles & Reports**: Issues cryptographic HMAC-SHA256 keyed proof signatures (`HMAC-SHA256:<sig>` and `PROOF-HMAC-SHA256:<sig>`) for bulk exports and SEC regulatory access reports.
- **Multi-Instance DB Concurrency**: Database-level pessimistic locking (`@Lock(LockModeType.PESSIMISTIC_WRITE)`), Flyway migrations, and atomic synchronization guaranteeing non-overlapping sequence assignment under multi-threaded parallel load.
- **Ambiguous Requirement Clarification (Scenario C)**: Translates the under-specified product mandate *"Regulators need to be able to audit access to client account data"* into a concrete, cryptographically-certified compliance reporting engine.
- **Live Direct-DB Tamper Simulator & Embedded Visualizer**: Interactive control portal (`http://localhost:8080`) with a 1-click database corruption simulator to demonstrate verification detection in real time.

---

## Security Credentials & Roles

| Role | Username | Password Source | Permitted API Operations |
| :--- | :--- | :--- | :--- |
| **`ROLE_INGEST`** | `ingest` | Configured via `${AUDIT_INGEST_PASS}` | Ingest new events (`POST /api/v1/audit/events`), query events (`GET /api/v1/audit/events`) |
| **`ROLE_AUDITOR`** | `auditor` | Configured via `${AUDIT_AUDITOR_PASS}` | Query events, run verification scans (`GET /api/v1/audit/verify`), bulk exports, compliance reports, verify checkpoints |
| **`ROLE_ADMIN`** | `admin` | Configured via `${AUDIT_ADMIN_PASS}` | All endpoints including Redaction (`POST /events/{id}/redact`), Retention (`POST /retention/apply`), Checkpoints, Tamper Simulator |

---

## Quick Start & Running Locally

### Prerequisites
- **Java Development Kit (JDK)**: Java 17 LTS or higher
- **Gradle**: Uses bundled Gradle Wrapper (`./gradlew` or `.\gradlew.bat`)

### 1. Run Automated Test Suite & JaCoCo Coverage Report
To verify compilation, Flyway migrations, unit tests, MockMvc security tests, archived tamper detection, concurrency, and JaCoCo coverage:
```bash
# Windows
.\gradlew.bat clean check

# macOS / Linux
./gradlew clean check
```
* **Test Summary**: 79 total test cases (78 Passed, 0 Failed, 0 Errors, 1 Skipped)
* **Test Report HTML**: `build/reports/tests/test/index.html`
* **JaCoCo Coverage HTML**: `build/reports/jacoco/test/html/index.html` (Line: 88.59%, Branch: 69.33%, Class: 100%)

### 2. Start the Service
```bash
# Windows
.\gradlew.bat bootRun

# macOS / Linux
./gradlew bootRun
```
Once started, the service runs at `http://localhost:8080`.

### 3. Open the Interactive Visualizer Portal
Open your web browser and navigate to:
👉 **`http://localhost:8080/index.html`** (or `http://localhost:8080`)

From the portal, you can:
- Ingest append-only events via UI forms with automatic server timestamping.
- Inspect the real-time audit trail and visual hash chain links.
- Run instant cryptographic chain verification scans and periodic checkpoints.
- **Trigger Live DB Tampering** to corrupt a record and watch the verification engine flag the exact tampered sequence index.
- Perform field-level redactions and verify zero hash drift.
- Generate certified regulatory compliance access reports.

---

## Architecture & Design Fundamentals

```
                  +-----------------------------------+
                  |  Client / Compliance Auditor      |
                  +-----------------------------------+
                                    |
     +------------------------------+------------------------------+
     |                              |                              |
POST /api/v1/audit/events    GET /api/v1/audit/verify     POST /api/v1/audit/events/{id}/redact
     |                              |                              |
     v                              v                              v
+------------------+      +-------------------+          +-------------------+
| Ingestion Engine |      | Verification Scan |          | Redaction Engine  |
+------------------+      +-------------------+          +-------------------+
     |                              |                              |
     +------------------------------+------------------------------+
                                    |
                                    v
                  +-----------------------------------+
                  | SHA-256 Hash Chain Engine         |
                  +-----------------------------------+
                                    |
                                    v
                  +-----------------------------------+
                  | Persistent Audit Database (Flyway)|
                  +-----------------------------------+
```

### Cryptographic Hash Formula
For record $R_i$ at sequence $i$:
$$\text{ContentHash}_i = \text{SHA256}(i \parallel \text{eventType} \parallel \text{actorId} \parallel \text{resourceType} \parallel \text{resourceId} \parallel \text{payloadHash}_i \parallel \text{timestampIso} \parallel \text{previousHash}_i)$$

Where:
- $\text{previousHash}_1 = \text{"0000000000000000000000000000000000000000000000000000000000000000"}$ (Genesis Hash)
- $\text{previousHash}_i = \text{recordHash}_{i-1}$ for $i > 1$
- $\text{payloadHash}$ uses Jackson canonical JSON serialization with key sorting (`MapperFeature.SORT_PROPERTIES_ALPHABETICALLY`).

---

## Deliverables & Documentation Index

- **`ATTESTATION.md`**: Formal candidate attestation.
- **`AI_USAGE_LOG.md`**: Complete log of AI prompts, code generation decisions, modifications, and engineering reasoning.
- **`ARCHITECTURE.md`**: Deep dive technical design document.
- **`SCENARIO_A.md`**: Core Greenfield Audit Log Service breakdown.
- **`SCENARIO_B.md`**: Retention, Redaction & Bulk Export breakdown.
- **`SCENARIO_C.md`**: Ambiguous Compliance Reporting breakdown.
- **`evidence/REQUIREMENTS_MATRIX.md`**: Requirement-to-code-to-test traceability matrix.
- **`evidence/VERIFICATION_REPORT.md`**: Executive engineering verification report.
- **`evidence/SECURITY_REVIEW.md`**: Security review and threat model audit.
- **`evidence/TEST_SUMMARY.md`**: Execution statistics and coverage breakdown.

---

## API Summary

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/v1/audit/events` | `POST` | Ingest new append-only event record |
| `/api/v1/audit/events` | `GET` | Multi-criteria query API with pagination |
| `/api/v1/audit/verify` | `GET` | Walk full chain and report integrity status |
| `/api/v1/audit/checkpoint` | `POST` | Create external periodic cryptographic chain checkpoint |
| `/api/v1/audit/checkpoint/{id}/verify` | `GET` | Verify recorded checkpoint against active chain |
| `/api/v1/audit/events/{id}/redact` | `POST` | Redact sensitive payload field preserving chain |
| `/api/v1/audit/retention/apply` | `POST` | Archive records older than N days with tombstones |
| `/api/v1/audit/export` | `GET` | Export self-contained verifiable JSON bundle |
| `/api/v1/compliance/client-access-report` | `GET` | Generate certified regulatory client access report |
| `/api/v1/audit/tamper-test` | `POST` | Direct DB mutation simulator for non-prod profile |

---

## Testing Approach, Limitations & Trade-Offs

### What is Covered
1. **Canonical Hashing & Determinism**: Unit tests verify SHA-256 calculation, property sorting, timestamp formatting, and field salt hashing (`HashChainEngineTest.java`).
2. **Ingestion & Chain Continuity**: Unit & integration tests verify sequential sequence numbers, `previousHash` linking to Genesis Zero (`0000...0000`), and full chain verification (`AuditLogServiceTest.java`).
3. **Database Tamper Detection**: Integration tests verify that modifying a record's raw DB fields immediately triggers `HASH_MISMATCH` at the exact altered sequence index (`AuditLogServiceTest.java`).
4. **Zero-Knowledge Redaction & Retention**: Tests confirm PII redaction (`"[REDACTED]"`) preserves original record hash and tombstone archiving preserves verification continuity (`RedactionAndRetentionTest.java`).
5. **Regulatory Compliance & Export**: Tests verify certified access reports with proof tokens and verifiable JSON export bundles (`ComplianceAndExportTest.java`).
6. **Phase Remediation Suite**: Comprehensive coverage of checkpoints, idempotency, rate limiting, payload size/depth limits, actor provenance, and failure rollback safety across 25 test classes (79 total tests).

### Limitations & Trade-Offs
- **$O(N)$ Verification Walk**: Verification engine performs a linear database walk, optimized by periodic Merkle root checkpointing (`POST /checkpoint`).
- **Database Support**: Built for PostgreSQL and ANSI SQL standard, using Flyway migrations for schema evolution. Tests run on H2 with pessimistic locking and skipped PostgreSQL Testcontainers when Docker is absent.
- **Authentication Scope**: Multi-Factor Authentication (MFA) and automatic credential expiration policies are intentionally not implemented in this service context and should be enforced upstream at the API gateway / IAM layer.

---

## Final Engineering Summary

- **Plan & Rationale**: Built a multi-layered, tamper-evident audit service balancing append-only immutability, zero-knowledge PII redaction, Flyway migrations, and certified compliance reporting.
- **Key Artifacts**: Production Java source code, JUnit 5 test suite, visual glassmorphism UI portal (`index.html`), architectural markdown specifications, and candidate attestation.
- **Risks & Mitigation**: Concurrency race conditions mitigated by atomic sequence locking and Flyway SQL unique constraints; clock skew mitigated by server UTC timestamp assignment.
- **Assumptions**: Audit records are generated via authorized internal services; database admin access is restricted, with tamper verification serving as the defense-in-depth detector.
