# Candidate Attestation & Evidence Mapping Statement

- **Full Name**: Aditya Rajput
- **Candidate Email**: adityarajput1628@users.noreply.github.com
- **GitHub Repository**: https://github.com/adityarajput1628/audit-log-service
- **Repository Branch**: `main`
- **Assignment Title**: Charles Schwab Audit Log Service – Production System Evaluation
- **Date Submitted**: 2026-09-23

> I, Aditya Rajput, attest that this submission is my own individual work, completed on my own machine and accounts, and that it honestly reflects my development process, architectural choices, and transparent use of AI tools.

---

## Explicit Claim-to-Evidence & Test Mapping Matrix

| Requirement / Scorecard ID | Claimed Feature / System Guarantee | Implementation Source Location | Verification Test Method | Status |
| :--- | :--- | :--- | :--- | :--- |
| **REQ-01 / REQ-04** | Scenario A/B/C Requirement Mapping | `README.md`, `SCENARIO_A/B/C.md` | `AuditLogServiceTest.java`, `ComplianceAndExportTest.java` | **VERIFIED** |
| **ARCH-01 / ARCH-02** | Layered Spring Architecture & DTOs | [AuditLogController.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/controller/AuditLogController.java), [AuditRecord.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/model/AuditRecord.java) | `SecurityAndAuthorizationTest.java` | **VERIFIED** |
| **ARCH-03 / TEST-05** | Authenticated Tombstone & Archived Record Integrity Verification | [HashChainEngine.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/crypto/HashChainEngine.java), [AuditLogService.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/service/AuditLogService.java), [RetentionService.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/service/RetentionService.java) | `ArchivedPayloadIntegrityTest.java` (11 scenarios), `AdversarialIntegrityTestSuiteTest.java` (Case B, E) | **VERIFIED** |
| **ARCH-04 / TEST-06** | Multi-Instance Concurrency & DB Lock Strategy | [AuditRecordRepository.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/repository/AuditRecordRepository.java), [AuditLogService.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/service/AuditLogService.java) | `ConcurrencyAndLockingTest.java` | **VERIFIED** |
| **SEC-01 / SEC-02 / SEC-05** | External Secret Management & Zero Hardcoded Secrets | [SecurityConfig.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/config/SecurityConfig.java), [ExportService.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/service/ExportService.java), [ComplianceService.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/service/ComplianceService.java) | `@Value` property injection bound to `${AUDIT_HMAC_SECRET}` & credentials | **VERIFIED** |
| **SEC-08 / BOLA-01** | BOLA / IDOR Tenant & Resource Authorization | [AuditLogController.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/controller/AuditLogController.java), [GlobalExceptionHandler.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/exception/GlobalExceptionHandler.java) | `SecurityAndAuthorizationTest.testBolaResourceAuthorization_nonAuditorCannotAccessOtherActorEvents()` | **VERIFIED** |
| **SEC-09 / CSRF-CORS** | Stateless Threat Model CSRF Policy & Explicit CORS Origins | [SecurityConfig.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/config/SecurityConfig.java), [ComplianceController.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/controller/ComplianceController.java) | Explicit allowed origins, no wildcard `*` with credentials | **VERIFIED** |
| **SEC-10 / PROF-01** | Spring Profile Isolation & Production H2 Console Guardrail | `application-dev.properties`, `application-prod.properties`, `application-test.properties` | H2 console strictly disabled (`spring.h2.console.enabled=false`) in prod | **VERIFIED** |
| **EXC-01 / ERR-01** | Custom Domain Exception Hierarchy & Unswallowed Exception Propagation | [AuditSerializationException.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/exception/AuditSerializationException.java), [AuditSecurityException.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/exception/AuditSecurityException.java), [GlobalExceptionHandler.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/exception/GlobalExceptionHandler.java) | Exception handlers map 403 Forbidden & 422 Unprocessable Entity | **VERIFIED** |
| **ADV-01 / TEST-15** | Adversarial Integrity Test Suite (Cases A - E) | [AdversarialIntegrityTestSuiteTest.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/test/java/com/schwab/auditlog/service/AdversarialIntegrityTestSuiteTest.java) | 5 explicit adversarial mutation tests (actorId, archived payload, metadata, digest, shortcut bypass) | **VERIFIED** |
| **TEST-08 / TEST-09** | Executable Test Suite & JaCoCo Coverage Enforcement | `build.gradle` (`jacoco` plugin) | `./gradlew test jacocoTestReport jacocoTestCoverageVerification` | **VERIFIED** |

---

## Reused Materials & Operational Risk Declarations

- **Reused Components**: Standard Spring Boot 3.3.0 starter packages (`spring-boot-starter-security`, `spring-boot-starter-validation`, `spring-boot-starter-data-jpa`), Jackson Object Mapper, Lombok, and JUnit 5 / Spring Security Test frameworks.
- **Operational Risks & Mitigations**:
  - *Risk*: Single-node in-memory H2 database used for zero-dependency execution.
  - *Mitigation*: Schema and repository structures are PostgreSQL compliant using standard JPA SQL abstractions; production profile enforces PostgreSQL dialect and validates DDL.
  - *Risk*: Secret management in deployment environments.
  - *Mitigation*: Externalized property bindings (`${AUDIT_HMAC_SECRET}`, `${AUDIT_ADMIN_PASS}`) seamlessly integrate with Kubernetes Secrets, AWS Secrets Manager, or HashiCorp Vault without source code modifications.

