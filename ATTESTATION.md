# Candidate Attestation & Executable Evidence Mapping Statement

- **Full Name**: Aditya Rajput
- **Candidate Email**: adityarajput1628@users.noreply.github.com
- **GitHub Repository**: https://github.com/adityarajput1628/audit-log-service
- **Repository Branch**: `master`
- **Assignment Title**: Charles Schwab Audit Log Service – Production System Evaluation
- **Date Verified**: 2026-09-30
- **Attested Commit SHA**: `7105caedbaad6bb3e981df523455986927a4d533` (`7105cae`)
- **Note**: This attestation document was finalized in the commit immediately following the attested commit, since a commit cannot reference its own hash. All code remediations, security filters, automated scheduler, multi-node tests, and JaCoCo coverage reports are consolidated in commit `7105cae`.

> I, Aditya Rajput, attest that this submission is my own individual work, completed on my own machine and accounts, and that it honestly reflects my development process, architectural choices, and transparent use of AI tools.

---

## The Core Verification Rule

> **"Never claim a requirement is satisfied merely because code appears to implement it. Every requirement must have implementation evidence AND executable verification evidence."**

---

## Explicit Claim-to-Evidence & Requirement Matrix

| Requirement ID | Description | Code Implementation Evidence | Executable Test Evidence | Status |
| :--- | :--- | :--- | :--- | :--- |
| **ARCH-01** | Layered Spring Boot Architecture | [AuditLogController.java](src/main/java/com/schwab/auditlog/controller/AuditLogController.java), [AuditLogService.java](src/main/java/com/schwab/auditlog/service/AuditLogService.java), [AuditRecordRepository.java](src/main/java/com/schwab/auditlog/repository/AuditRecordRepository.java) | `SecurityAndAuthorizationComprehensiveTest` | **PASS** |
| **ARCH-03** | Archived Payload Integrity Verification | [HashChainEngine.java](src/main/java/com/schwab/auditlog/crypto/HashChainEngine.java), [RetentionService.java](src/main/java/com/schwab/auditlog/service/RetentionService.java) | `ArchivedPayloadIntegrityTest`, `AdversarialIntegrityTestSuiteTest` | **PASS** |
| **ARCH-04a** | Multi-Context Concurrency Simulation (H2) | [AuditRecordRepository.java](src/main/java/com/schwab/auditlog/repository/AuditRecordRepository.java), [AuditLogService.java](src/main/java/com/schwab/auditlog/service/AuditLogService.java) | `MultiInstanceContextSimulationTest.testTwoIndependentSpringContextsWritingConcurrently` | **PASS** |
| **ARCH-04b** | Multi-Instance Container Execution (PostgreSQL Testcontainers) | [build.gradle](build.gradle) (`org.postgresql:postgresql:42.7.3`), [MultiInstancePostgresTest.java](src/test/java/com/schwab/auditlog/service/MultiInstancePostgresTest.java) | `MultiInstancePostgresTest` (Testcontainers PostgreSQL 16 code present; test skipped due to host Docker daemon unavailability) | **PARTIAL** |
| **SEC-01** | Zero Hardcoded Production Secrets | [SecurityConfig.java](src/main/java/com/schwab/auditlog/config/SecurityConfig.java), [ExportService.java](src/main/java/com/schwab/auditlog/service/ExportService.java), [ComplianceService.java](src/main/java/com/schwab/auditlog/service/ComplianceService.java), [RedactionService.java](src/main/java/com/schwab/auditlog/service/RedactionService.java) | Repository Grep Audit | **PASS** |
| **SEC-03** | RBAC & Endpoint Authorization | [SecurityConfig.java](src/main/java/com/schwab/auditlog/config/SecurityConfig.java) | `SecurityAndAuthorizationComprehensiveTest` | **PASS** |
| **SEC-07** | Profile-Gated Demo Tamper Endpoint | [TamperTestController.java](src/main/java/com/schwab/auditlog/controller/TamperTestController.java) (`@Profile("!prod")`) | `SecurityAndAuthorizationComprehensiveTest` | **PASS** |
| **SEC-08** | BOLA / IDOR Tenant Authorization | [AuditLogController.java](src/main/java/com/schwab/auditlog/controller/AuditLogController.java) | `SecurityAndAuthorizationComprehensiveTest.testBolaResourceAuthorizationForNonAuditor` | **PASS** |
| **SEC-09** | Stateless CSRF Policy & CORS Enforcement | [SecurityConfig.java](src/main/java/com/schwab/auditlog/config/SecurityConfig.java) | `SecurityAndAuthorizationComprehensiveTest.testCorsPreflightAllowedOrigins` | **PASS** |
| **SEC-10** | Production H2 Console Isolation Guardrail | [application-prod.properties](src/main/resources/application-prod.properties) | `SecurityAndAuthorizationComprehensiveTest` | **PASS** |
| **EXC-01** | Structured Global Exception Handling | [GlobalExceptionHandler.java](src/main/java/com/schwab/auditlog/exception/GlobalExceptionHandler.java) | `DetailedCoverageExpansionTest`, `ValidationAndSerializationFailureTest` | **PASS** |
| **TEST-06** | Executable JaCoCo Coverage Enforcement | [build.gradle](build.gradle) (`check.dependsOn jacocoTestCoverageVerification`) | `./gradlew clean check` (88.48% Line, 69.14% Branch Coverage) | **PASS** |
| **TEST-15** | Adversarial Integrity Test Suite | [AdversarialIntegrityTestSuiteTest.java](src/test/java/com/schwab/auditlog/service/AdversarialIntegrityTestSuiteTest.java) | 5 explicit tamper mutation tests (Cases A-E) | **PASS** |

---

## Verification Evidence Summary
- **Total Test Cases**: **86** (85 Passed, 0 Failed, 0 Errors, 1 Skipped across 27 Test Classes)
- **JaCoCo Line Coverage**: **88.48%** (952/1076 lines covered, Threshold: >= 80%)
- **JaCoCo Branch Coverage**: **69.14%** (242/350 branches covered, Threshold: >= 60%)
- **Class Coverage**: **100%** (51/51 classes covered)
- **Zero Secrets Audit**: 0 secret literals or salt fallback strings in tracked repository files.
- **Evidence Package Location**: `evidence/` folder containing requirements matrix, test summary, security review, and verification report.
