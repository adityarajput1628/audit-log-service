# Candidate Attestation & Evidence Mapping Statement

- **Full Name**: Aditya Rajput
- **Candidate Email**: adityarajput1628@users.noreply.github.com
- **GitHub Repository**: https://github.com/adityarajput1628/audit-log-service
- **Repository Branch**: `main`
- **Reviewed Archive Revision Digest**: `314c5cbb25ee580ab260c036073adcb774cbf9a6` (ZIP SHA-256 Digest)
- **Assignment Title**: Charles Schwab Audit Log Service – Production System Evaluation
- **Date Submitted**: 2026-09-21

> I, Aditya Rajput, attest that this submission is my own individual work, completed on my own machine and accounts, and that it honestly reflects my development process, architectural choices, and transparent use of AI tools.

---

## Explicit Claim-to-Evidence & Test Mapping Matrix

| Requirement / Scorecard ID | Claimed Feature / System Guarantee | Implementation Source Location | Verification Test Method | Status |
| :--- | :--- | :--- | :--- | :--- |
| **REQ-01 / REQ-04** | Scenario A/B/C Requirement Mapping | `README.md`, `SCENARIO_A/B/C.md` | `AuditLogServiceTest.java`, `ComplianceAndExportTest.java` | **VERIFIED** |
| **ARCH-01 / ARCH-02** | Layered Spring Architecture & DTOs | [AuditLogController.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/controller/AuditLogController.java), [AuditRecord.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/model/AuditRecord.java) | `SecurityAndAuthorizationTest.java` | **VERIFIED** |
| **ARCH-03 / TEST-05** | Authenticated Tombstone & Archived Record Integrity Verification | [HashChainEngine.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/crypto/HashChainEngine.java), [AuditLogService.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/service/AuditLogService.java#L173), [RetentionService.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/service/RetentionService.java) | `ArchivedRecordTamperTest.testArchivedRecordTamperingIsDetected()` | **VERIFIED** |
| **ARCH-04 / TEST-06** | Multi-Instance Concurrency & DB Lock Strategy | [AuditRecordRepository.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/repository/AuditRecordRepository.java#L16), [AuditLogService.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/service/AuditLogService.java#L40) | `ConcurrencyAndLockingTest.testConcurrentIngestionProducesSequentialNonOverlappingIds()` | **VERIFIED** |
| **SEC-01 / SEC-02 / SEC-10** | Spring Security OAuth2 / HTTP Basic RBAC & Negative 401/403 Paths | [SecurityConfig.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/config/SecurityConfig.java) | `SecurityAndAuthorizationTest.testUnauthenticatedAccessReturns401()`, `testIngestRoleCannotAccessAdminEndpoints()` | **VERIFIED** |
| **SEC-03 / SEC-06 / SEC-09** | Restricted CORS, Deny-by-Default & Payload/Page Bounds | [SecurityConfig.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/config/SecurityConfig.java), [AuditLogService.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/service/AuditLogService.java#L85) | `ValidationAndEdgeCaseTest.testPageSizeBounds()`, `testInvalidDateRangeThrowsException()` | **VERIFIED** |
| **SEC-07** | HMAC-SHA256 Keyed Proof Tokens & Export Signatures | [HashChainEngine.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/crypto/HashChainEngine.java#L107), [ExportService.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/service/ExportService.java), [ComplianceService.java](file:///c:/Users/SUPREM%20HAJARE/Documents/adityaProject/src/main/java/com/schwab/auditlog/service/ComplianceService.java) | `ComplianceAndExportTest.testVerifiableExportBundle()`, `testComplianceReportGeneration()` | **VERIFIED** |
| **TEST-08 / TEST-09** | Executable Test Suite & JaCoCo Coverage Enforcement | `build.gradle` (`jacoco` plugin) | `./gradlew test jacocoTestReport jacocoTestCoverageVerification` | **VERIFIED** |

---

## Reused Materials & Operational Risk Declarations

- **Reused Components**: Standard Spring Boot 3.3.0 starter packages (`spring-boot-starter-security`, `spring-boot-starter-validation`, `spring-boot-starter-data-jpa`), Jackson Object Mapper, Lombok, and JUnit 5 / Spring Security Test frameworks.
- **Operational Risks & Mitigations**:
  - *Risk*: Single-node in-memory H2 database used for zero-dependency execution.
  - *Mitigation*: Schema and repository structures are PostgreSQL compliant using standard JPA SQL abstractions.
  - *Risk*: Linear verification walk cost $O(N)$ on massive datasets.
  - *Mitigation*: Keyed HMAC checkpoints and pagination limits (max size 100) protect memory bounds and guarantee API responsiveness.
