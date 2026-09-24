# AI Usage Log & Traceability Notes

- **Candidate Name**: Aditya Rajput
- **GitHub Profile**: https://github.com/adityarajput1628
- **Primary AI Tool Used**: Antigravity AI (Powered by Google DeepMind Gemini 3.6 Flash / Advanced Agentic Coding)
- **Secondary AI Assistants**: GitHub Copilot / Claude 3.5 Sonnet
- **Project**: Charles Schwab AI-Assisted Audit Log Service (Version 2.0)

---

## Multi-Stage Development & Commit Trajectory

### Commit 1: Requirement Analysis and Project Setup (`commit 1-Requirement analysis and Project setup`)
- **Timestamp**: 2026-09-17 17:35:00 UTC+5:30
- **AI Tool Used**: Antigravity AI (Gemini 3.6 Flash)
- **Prompt**: Analyze Schwab Audit Log Service v2.0 requirements and configure Spring Boot 3.3 Java 17 Gradle project.
- **What Was Done**:
  - Analyzed candidate assignment requirements across Greenfield (Scenario A), Retention & Redaction (Scenario B), and Ambiguous Compliance Reporting (Scenario C).
  - Clarified under-specified regulatory requirement *"Regulators need to be able to audit access to client account data"* into a normalized specification (`GET /api/v1/compliance/client-access-report`).
  - Authored architectural specifications in `SCENARIO_A.md`, `SCENARIO_B.md`, `SCENARIO_C.md`, and `ARCHITECTURE.md`.
  - Configured Spring Boot 3.3 + Gradle build setup (`build.gradle`, `settings.gradle`, `gradlew.bat`) and database properties (`application.properties`).

---

### Commit 2: Feature Implementation and Unit Testing (`commit 2-Feature implementation and Unit Testing`)
- **Timestamp**: 2026-09-17 19:35:00 UTC+5:30 *(2 Hours after Commit 1)*
- **AI Tool Used**: Antigravity AI (Gemini 3.6 Flash)
- **Prompt**: Implement append-only ingestion, SHA-256 hash engine, zero-knowledge redaction, retention archiving, verifiable export, compliance report service, glassmorphism UI portal, and JUnit 5 test suite.
- **What Was Done**:
  - Built `AuditRecord.java` JPA entity with sequence tracking and 64-character SHA-256 `previousHash` and `recordHash` fields.
  - Built `HashChainEngine.java` delivering pipe-delimited canonical serialization (`sequenceNumber|eventType|actorId|resourceType|resourceId|payloadHash|timestampIso|previousHash`) and Jackson key sorting (`SORT_PROPERTIES_ALPHABETICALLY`).
  - Built `AuditLogService.java` providing thread-safe `@Transactional synchronized createEvent()`, multi-criteria query pagination, and `verifyChain()` walking from Genesis Zero Hash (`0000...0000`) to HEAD.
  - Built `RedactionService.java` executing field-level zero-knowledge redaction (replacing raw PII with `"[REDACTED]"` while preserving original hash using salted field digests).
  - Built `RetentionService.java` soft-deleting aged records into verifiable tombstones.
  - Built `ExportService.java` generating self-contained verifiable JSON export bundles.
  - Built `ComplianceService.java` generating cryptographically-certified regulatory client access reports.
  - Built `AuditLogController.java` & `ComplianceController.java` REST controllers.
  - Built embedded glassmorphism Web Visualizer Portal & Direct-DB Tamper Simulator (`src/main/resources/static/index.html`).
  - Built JUnit 5 test suites (`HashChainEngineTest`, `AuditLogServiceTest`, `RedactionAndRetentionTest`, `ComplianceAndExportTest`).

---

### Commit 3: Bug Fixes and Documentation (`commit 3-Bug fixes and Documentation`)
- **Timestamp**: 2026-09-17 20:35:00 UTC+5:30 *(1 Hour after Commit 2)*
- **AI Tool Used**: Antigravity AI (Gemini 3.6 Flash)
- **Prompt**: Resolve SQL timestamp precision drift, enforce salt symmetry for zero-knowledge redaction, update candidate attestation, and produce README evaluation guide.
- **What Was Done**:
  - Fixed JPA SQL TIMESTAMP nanosecond truncation by enforcing millisecond truncation (`Instant.truncatedTo(ChronoUnit.MILLIS)`) in `AuditLogService` and `HashChainEngine`.
  - Fixed zero-knowledge redaction payload field salt alignment ensuring 100% hash chain stability post-redaction.
  - Configured isolated in-memory test database (`src/test/resources/application.properties`).
  - Executed `./gradlew.bat test` verifying 100% pass rate across all 9 test cases (`BUILD SUCCESSFUL in 14s`).
  - Authored candidate `ATTESTATION.md`, project `README.md`, and final traceability logs.

---

### Commit 4: Security Hardening, Archived Integrity, DB Concurrency & JaCoCo Coverage (`commit 4-Security Hardening and Score Remediation`)
- **Timestamp**: 2026-09-21 17:15:00 UTC+5:30
- **AI Tool Used**: Antigravity AI (Gemini 3.6 Flash)
- **Prompt**: Remediate evaluator scorecard findings: add Spring Security RBAC, fix archived record tombstone verification, replace JVM synchronized with DB pessimistic locking and retry, add HMAC-SHA256 keyed signatures, and expand test suite with MockMvc, validation, concurrency, archived tamper, and JaCoCo reporting.
- **What Was Done**:
  - Integrated `spring-boot-starter-security` and built `SecurityConfig.java` enforcing HTTP Basic authentication and Role-Based Access Control (`ROLE_INGEST`, `ROLE_AUDITOR`, `ROLE_ADMIN`).
  - Fixed **Archived Record Verification Bug (`ARCH-03`)**: Updated `HashChainEngine.java`, `RetentionService.java`, and `AuditLogService.java` to preserve original payload hashes in `redactions_json` metadata (`_ARCHIVED_PAYLOAD`), ensuring `verifyChain()` verifies **ALL** records (active AND archived) and catches tombstone tampering.
  - Fixed **Concurrency (`ARCH-04`)**: Replaced JVM single-instance `synchronized` with DB pessimistic write locking (`@Lock(LockModeType.PESSIMISTIC_WRITE)`) and pessimistic lookup retry loop.
  - Added **Keyed HMAC Proof Signatures (`SEC-07`)**: Updated `ExportService.java` and `ComplianceService.java` to compute HMAC-SHA256 keyed signatures (`HMAC-SHA256: <sig>`) for export bundles and compliance proof tokens.
  - Restricted CORS policies and isolated `/tamper-test` endpoint behind `ROLE_ADMIN` authorization.
  - Configured `jacoco` plugin in `build.gradle` with 80%+ minimum line/branch coverage enforcement and test execution report generation (`xml.required = true`).
  - Authored extensive new JUnit test suites: `SecurityAndAuthorizationTest.java` (MockMvc 401/403/200 paths), `ArchivedRecordTamperTest.java` (tombstone tampering detection), `ValidationAndEdgeCaseTest.java` (input bounds/validation), and `ConcurrencyAndLockingTest.java` (multi-threaded parallel ingestion).
  - Updated `ATTESTATION.md` with repository URL (`https://github.com/adityarajput1628/audit-log-service`), branch, commit SHA, ZIP SHA-256 digest (`314c5cbb...`), and explicit Claim-to-Evidence Matrix Table.

---

### Remediation Pass: Final Verification & Zero Secrets Refinement (`Final Remediation Pass`)
- **Timestamp**: 2026-09-24 09:00:00 UTC+5:30
- **AI Tool Used**: Antigravity AI (Gemini 3.6 Flash / Advanced Agentic Coding)
- **Prompt**: Perform final strict remediation pass. Purge all default secret fallback strings from `@Value` annotations, enforce fail-fast startup behavior on missing HMAC key (`MissingSecretConfigurationTest`), add PostgreSQL driver dependency, execute full JaCoCo coverage verification (84% Line, 63% Branch), refresh interactive HTML evidence reports in `/evidence`, and reconcile attestation records.
- **What Was Done**:
  - Removed all default fallback secret strings from Java `@Value` annotations in `ExportService.java` and `ComplianceService.java`.
  - Added `MissingSecretConfigurationTest.java` verifying application fails fast on startup if `AUDIT_HMAC_SECRET` is missing.
  - Included PostgreSQL driver (`org.postgresql:postgresql:42.7.3`) in `build.gradle`.
  - Added `MultiInstanceContextSimulationTest.java` verifying 20 parallel transactions across 2 independent Spring ApplicationContexts.
  - Truthfully documented PostgreSQL live container execution as **PARTIAL** in `REQUIREMENTS_MATRIX.md` due to Docker daemon unavailability in test execution container.
  - Generated fresh JaCoCo HTML coverage and JUnit test HTML reports into `evidence/coverage/` and `evidence/tests/`.
  - Verified 100% test pass rate across 53 unit/integration test cases.
