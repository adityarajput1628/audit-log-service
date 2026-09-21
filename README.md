# AI-Assisted Software Engineering System – Audit Log Service
**Charles Schwab & Co., Inc. – Confidential & Proprietary (Version 2.0)**

---

## Executive Summary

This repository contains a production-grade, tamper-evident **Audit Log Service** engineered using **Java 17**, **Spring Boot 3.3**, and **Gradle**. 

The system guarantees:
- **P0 Security Boundary & RBAC Authorization**: Enforces Spring Security HTTP Basic authentication with Role-Based Access Control (`ROLE_INGEST`, `ROLE_AUDITOR`, `ROLE_ADMIN`), explicit CORS origins, and isolated sensitive operations.
- **Append-Only Immutability**: No update or delete operations on audit records.
- **Cryptographic Tamper Evidence**: Sequential SHA-256 hash chaining linking every event to the prior record's digest back to a defined Genesis Zero hash.
- **Archived Record Integrity Verification**: Cryptographically verifies **ALL** records (active AND archived tombstones) in `verifyChain()`, catching direct database tampering on archived tombstones or metadata.
- **Zero-Knowledge Field Redaction (Scenario B)**: Masks sensitive PII (account numbers, SSNs) to `"[REDACTED]"` while preserving 100% cryptographic hash chain validity using salted field digests.
- **Policy-Based Retention (Scenario B)**: Soft-deletes aged records using verifiable tombstones without producing false-positive chain breaks.
- **Keyed HMAC Proof Bundles & Reports**: Issues non-repudiable HMAC-SHA256 keyed signatures (`HMAC-SHA256:<sig>` and `PROOF-HMAC-SHA256:<sig>`) for bulk exports and SEC regulatory access reports.
- **Multi-Instance DB Concurrency**: Database-level pessimistic locking (`@Lock(LockModeType.PESSIMISTIC_WRITE)`) and atomic synchronization guaranteeing non-overlapping sequence assignment under multi-threaded parallel load.
- **Ambiguous Requirement Clarification (Scenario C)**: Translates the under-specified product mandate *"Regulators need to be able to audit access to client account data"* into a concrete, cryptographically-certified compliance reporting engine.
- **Live Direct-DB Tamper Simulator & Embedded Visualizer**: Interactive control portal (`http://localhost:8080`) with a 1-click database corruption simulator to demonstrate verification detection in real time.

---

## Security Credentials & Roles

| Role | Username | Password | Permitted API Operations |
| :--- | :--- | :--- | :--- |
| **`ROLE_INGEST`** | `ingest` | `ingest123` | Ingest new events (`POST /api/v1/audit/events`), query events (`GET /api/v1/audit/events`) |
| **`ROLE_AUDITOR`** | `auditor` | `auditor123` | Query events, run verification scans (`GET /api/v1/audit/verify`), bulk exports, compliance reports |
| **`ROLE_ADMIN`** | `admin` | `admin123` | All endpoints including Redaction (`POST /events/{id}/redact`), Retention (`POST /retention/apply`), Tamper Simulator |

---

## Quick Start & Running Locally

### Prerequisites
- **Java Development Kit (JDK)**: Java 17 LTS or higher
- **Gradle**: Uses bundled Gradle Wrapper (`./gradlew` or `.\gradlew.bat`)

### 1. Run Automated Test Suite & JaCoCo Coverage Report
To verify compilation, unit tests, MockMvc security tests, archived tamper detection, concurrency, and JaCoCo coverage:
```bash
# Windows
.\gradlew.bat test jacocoTestReport jacocoTestCoverageVerification

# macOS / Linux
./gradlew test jacocoTestReport jacocoTestCoverageVerification
```
* **Test Report HTML**: `build/reports/tests/test/index.html`
* **JaCoCo Coverage HTML**: `build/reports/jacoco/test/html/index.html`

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
- Ingest append-only events via UI forms.
- Inspect the real-time audit trail and visual hash chain links.
- Run instant cryptographic chain verification scans.
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
                  | Persistent Audit Database (H2/SQL)|
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

- **`ATTESTATION.md`**: Formal candidate attestation (§0.4 requirement).
- **`AI_USAGE_LOG.md`**: Complete log of AI prompts, code generation decisions, modifications, and engineering reasoning.
- **`ARCHITECTURE.md`**: Deep dive technical design document.
- **`SCENARIO_A.md`**: Core Greenfield Audit Log Service breakdown.
- **`SCENARIO_B.md`**: Retention, Redaction & Bulk Export breakdown.
- **`SCENARIO_C.md`**: Ambiguous Compliance Reporting breakdown.

---

## API Summary

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/v1/audit/events` | `POST` | Ingest new append-only event record |
| `/api/v1/audit/events` | `GET` | Multi-criteria query API with pagination |
| `/api/v1/audit/verify` | `GET` | Walk full chain and report integrity status |
| `/api/v1/audit/events/{id}/redact` | `POST` | Redact sensitive payload field preserving chain |
| `/api/v1/audit/retention/apply` | `POST` | Archive records older than N days |
| `/api/v1/audit/export` | `GET` | Export self-contained verifiable JSON bundle |
| `/api/v1/compliance/client-access-report` | `GET` | Generate certified regulatory client access report |
| `/api/v1/audit/tamper-test` | `POST` | Direct DB mutation simulator for demonstration |

---

## Testing Approach, Limitations & Trade-Offs

### What is Covered
1. **Canonical Hashing & Determinism**: Unit tests verify SHA-256 calculation, property sorting, timestamp formatting, and field salt hashing (`HashChainEngineTest.java`).
2. **Ingestion & Chain Continuity**: Unit & integration tests verify sequential sequence numbers, `previousHash` linking to Genesis Zero (`0000...0000`), and full chain verification (`AuditLogServiceTest.java`).
3. **Database Tamper Detection**: Integration tests verify that modifying a record's raw DB fields immediately triggers `HASH_MISMATCH` at the exact altered sequence index (`AuditLogServiceTest.java`).
4. **Zero-Knowledge Redaction & Retention**: Tests confirm PII redaction (`"[REDACTED]"`) preserves original record hash and tombstone archiving preserves verification continuity (`RedactionAndRetentionTest.java`).
5. **Regulatory Compliance & Export**: Tests verify certified access reports with proof tokens and verifiable JSON export bundles (`ComplianceAndExportTest.java`).

### Limitations & Trade-Offs
- **$O(N)$ Verification Walk**: Current verification engine performs a linear database walk. For high-volume production scale (100M+ events), periodic Merkle root checkpointing should be introduced.
- **Single-Node DB Scope**: Uses in-memory H2 for prototype zero-dependency runnability. Production deployment requires PostgreSQL with write-ahead replication.

---

## Final Engineering Summary

- **Plan & Rationale**: Built a multi-layered, tamper-evident audit service balancing append-only immutability, zero-knowledge PII redaction, and certified compliance reporting.
- **Key Artifacts**: Production Java source code, JUnit 5 test suite, visual glassmorphism UI portal (`index.html`), architectural markdown specifications (`ARCHITECTURE.md`, `SCENARIO_A.md`, `SCENARIO_B.md`, `SCENARIO_C.md`), `AI_USAGE_LOG.md`, and candidate `ATTESTATION.md`.
- **Risks & Mitigation**: Concurrency race conditions mitigated by atomic sequence locking and SQL unique constraints; clock skew mitigated by server UTC timestamp assignment.
- **Assumptions**: Audit records are generated via authorized internal services; database admin access is restricted, with tamper verification serving as the defense-in-depth detector.

