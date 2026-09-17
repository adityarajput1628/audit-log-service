# AI-Assisted Software Engineering System – Audit Log Service
**Charles Schwab & Co., Inc. – Confidential & Proprietary (Version 2.0)**

---

## Executive Summary

This repository contains a production-grade, tamper-evident **Audit Log Service** engineered using **Java 17**, **Spring Boot 3.3**, and **Gradle**. 

The system guarantees:
- **Append-Only Immutability**: No update or delete operations on audit records.
- **Cryptographic Tamper Evidence**: Sequential SHA-256 hash chaining linking every event to the prior record's digest back to a defined Genesis Zero hash.
- **Zero-Knowledge Field Redaction (Scenario B)**: Masks sensitive PII (account numbers, SSNs) to `"[REDACTED]"` while preserving 100% cryptographic hash chain validity using salted field digests.
- **Policy-Based Retention (Scenario B)**: Soft-deletes aged records using verifiable tombstones without producing false-positive chain breaks.
- **Verifiable Bulk Export (Scenario B)**: Generates self-contained JSON bundles with inclusion proofs for third-party regulatory validation.
- **Ambiguous Requirement Clarification (Scenario C)**: Translates the under-specified product mandate *"Regulators need to be able to audit access to client account data"* into a concrete, cryptographically-certified compliance reporting engine.
- **Live Direct-DB Tamper Simulator & Embedded Visualizer**: Interactive control portal (`http://localhost:8080`) with a 1-click database corruption simulator to demonstrate verification detection in real time.

---

## Quick Start & Running Locally

### Prerequisites
- **Java Development Kit (JDK)**: Java 17 LTS or higher
- **Gradle**: Uses bundled Gradle Wrapper (`./gradlew` or `.\gradlew.bat`)

### 1. Run Automated Test Suite
To verify compilation, unit tests, integration tests, and tamper detection:
```bash
# Windows
.\gradlew.bat test

# macOS / Linux
./gradlew test
```

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
