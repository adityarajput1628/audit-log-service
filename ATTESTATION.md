# Candidate Attestation & Executable Evidence Mapping Statement

- **Full Name**: Aditya Rajput
- **Candidate Email**: adityarajput1628@users.noreply.github.com
- **GitHub Repository**: https://github.com/adityarajput1628/audit-log-service
- **Repository Branch**: `master`
- **Assignment Title**: Charles Schwab Audit Log Service – Production System Evaluation
- **Base Commit SHA**: `16f0f5676bfed3c76fa0180231282fa07617f2f5` (uncommitted working tree remediation changes ready for staging)
- **Date Verified**: 2026-09-24

> I, Aditya Rajput, attest that this submission is my own individual work, completed on my own machine and accounts, and that it honestly reflects my development process, architectural choices, and transparent use of AI tools.

---

## The Core Verification Rule

> **"Never claim a requirement is satisfied merely because code appears to implement it. Every requirement must have implementation evidence AND executable verification evidence."**

---

## Explicit Claim-to-Evidence & Requirement Matrix

| Requirement ID | Description | Code Implementation Evidence | Executable Test Evidence | Status |
| :--- | :--- | :--- | :--- | :--- |
| **ARCH-01** | Layered Spring Boot Architecture | [AuditLogController.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/controller/AuditLogController.java), [AuditLogService.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/service/AuditLogService.java), [AuditRecordRepository.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/repository/AuditRecordRepository.java) | `SecurityAndAuthorizationComprehensiveTest` | **PASS** |
| **ARCH-03** | Archived Payload Integrity Verification | [HashChainEngine.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/crypto/HashChainEngine.java), [RetentionService.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/service/RetentionService.java) | `ArchivedPayloadIntegrityTest`, `AdversarialIntegrityTestSuiteTest` | **PASS** |
| **ARCH-04a** | Multi-Context Concurrency Simulation (H2) | [AuditRecordRepository.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/repository/AuditRecordRepository.java), [AuditLogService.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/service/AuditLogService.java) | `MultiInstanceContextSimulationTest.testTwoIndependentSpringContextsWritingConcurrently` | **PASS** |
| **ARCH-04b** | Multi-Instance Container Execution (PostgreSQL Testcontainers) | [build.gradle](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/build.gradle) (`org.postgresql:postgresql:42.7.3`), [MultiInstancePostgresTest.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/test/java/com/schwab/auditlog/service/MultiInstancePostgresTest.java) | `MultiInstancePostgresTest` (Testcontainers PostgreSQL 16 code present; test skipped due to host Docker daemon unavailability) | **PARTIAL** |
| **SEC-01** | Zero Hardcoded Production Secrets | [SecurityConfig.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/config/SecurityConfig.java), [ExportService.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/service/ExportService.java), [ComplianceService.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/service/ComplianceService.java), [RedactionService.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/service/RedactionService.java) | Repository Grep Audit | **PASS** |
| **SEC-03** | RBAC & Endpoint Authorization | [SecurityConfig.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/config/SecurityConfig.java) | `SecurityAndAuthorizationComprehensiveTest` | **PASS** |
| **SEC-07** | Profile-Gated Demo Tamper Endpoint | [TamperTestController.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/controller/TamperTestController.java) (`@Profile("!prod")`) | `SecurityAndAuthorizationComprehensiveTest` | **PASS** |
| **SEC-08** | BOLA / IDOR Tenant Authorization | [AuditLogController.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/controller/AuditLogController.java) | `SecurityAndAuthorizationComprehensiveTest.testBolaResourceAuthorizationForNonAuditor` | **PASS** |
| **SEC-09** | Stateless CSRF Policy & CORS Enforcement | [SecurityConfig.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/config/SecurityConfig.java) | `SecurityAndAuthorizationComprehensiveTest.testCorsPreflightAllowedOrigins` | **PASS** |
| **SEC-10** | Production H2 Console Isolation Guardrail | [application-prod.properties](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/resources/application-prod.properties) | `SecurityAndAuthorizationComprehensiveTest` | **PASS** |
| **EXC-01** | Structured Global Exception Handling | [GlobalExceptionHandler.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/exception/GlobalExceptionHandler.java) | `DetailedCoverageExpansionTest`, `ValidationAndSerializationFailureTest` | **PASS** |
| **TEST-06** | Executable JaCoCo Coverage Enforcement | [build.gradle](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/build.gradle) (`check.dependsOn jacocoTestCoverageVerification`) | `./gradlew clean check` (88.89% Line, 69.68% Branch Coverage) | **PASS** |
| **TEST-15** | Adversarial Integrity Test Suite | [AdversarialIntegrityTestSuiteTest.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/test/java/com/schwab/auditlog/service/AdversarialIntegrityTestSuiteTest.java) | 5 explicit tamper mutation tests (Cases A-E) | **PASS** |

---

## Verification Evidence Summary
- **Total Test Cases**: **62** (61 Passed, 0 Failed, 0 Errors, 1 Skipped)
- **JaCoCo Line Coverage**: **88.89%** (648/729 lines covered, Threshold: >= 80%)
- **JaCoCo Branch Coverage**: **69.68%** (131/188 branches covered, Threshold: >= 60%)
- **Zero Secrets Audit**: 0 secret literals or salt fallback strings in tracked repository files.
- **Evidence Package Location**: `/evidence/` folder containing interactive JUnit (`evidence/tests/`) and JaCoCo (`evidence/coverage/`) reports.
