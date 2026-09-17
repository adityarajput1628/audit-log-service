# AI Usage Log & Traceability Notes

- **Candidate Name**: Aditya Rajput
- **GitHub Profile**: https://github.com/adityarajput1628
- **Primary AI Tool Used**: Antigravity AI (Powered by Google DeepMind Gemini 3.6 Flash / Advanced Agentic Coding)
- **Secondary AI Assistants**: GitHub Copilot / Claude 3.5 Sonnet
- **Project**: Charles Schwab AI-Assisted Audit Log Service (Version 2.0)

---

## 3-Stage Development & Commit Trajectory

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
