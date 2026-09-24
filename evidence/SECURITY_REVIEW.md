# Security Review & Threat Model Audit (SECURITY_REVIEW.md)

## 1. Secrets & Credentials Policy & Audit Verification
- **Zero Committed Production Secrets**: All production credentials, database passwords, and HMAC secrets are injected strictly via mandatory environment variables (`${AUDIT_HMAC_SECRET}`, `${AUDIT_INGEST_PASS}`, `${AUDIT_ADMIN_PASS}`, `${AUDIT_AUDITOR_PASS}`) in `application-prod.properties` and `application.properties`.
- **Zero Secret Fallback Strings**:
  - Removed all default secret fallback strings from Java `@Value` annotations in `ExportService.java`, `ComplianceService.java`, and `RedactionService.java` (`@Value("${schwab.security.hmac.secret}")`).
  - Added `MissingSecretConfigurationTest.java` to explicitly prove that starting the service without `AUDIT_HMAC_SECRET` configured fails fast with an `IllegalArgumentException` rather than silently using a weak default fallback key.
- **Exposed Test Credential Purge Audit**:
  - Comprehensive automated codebase scan (`grep_search`) was executed across all `.java`, `.properties`, `.yml`, `.md`, and documentation files.
  - Search results for legacy/exposed credentials:
    - `ingest123`: **0 occurrences**
    - `auditor123`: **0 occurrences**
    - `admin123`: **0 occurrences**
    - `SCHWAB_SALT`: **0 occurrences**
    - `test-only-hmac-secret`: **0 occurrences**
    - `schwab_dev_hmac_secret_key_32bytes`: **0 occurrences in codebase source files**
    - `schwab_dev_db_pass_2026`: **0 occurrences in codebase source files**
  - **Verdict**: Zero hardcoded credential or salt literals exist in the project repository. Test configuration uses explicit, isolated non-secret test placeholders (`ingest_test_user`, `ingest_test_pass`, `test_hmac_secret_key_for_unit_tests`).

## 2. Profile-Gated Demo Endpoints
- **Tamper Endpoint Hardening**: `/api/v1/audit/tamper-test` is moved to `TamperTestController.java` annotated with `@Profile("!prod")`. In production builds (`spring.profiles.active=prod`), the bean is physically absent from Spring context, returning HTTP 404 Not Found.

## 3. Authentication & Authorization Architecture
- **Authentication**: HTTP Basic Authentication with BCrypt password encoding (`BCryptPasswordEncoder`).
- **Role-Based Access Control (RBAC)**:
  - `ROLE_INGEST`: Ingest events (`POST /api/v1/audit/events`).
  - `ROLE_AUDITOR`: Read events (`GET /api/v1/audit/events`), verify chain (`GET /api/v1/audit/verify`), export audit logs (`GET /api/v1/audit/export`), compliance report (`GET /api/v1/compliance/client-access-report`).
  - `ROLE_ADMIN`: Full administrative control including redaction (`POST /events/{id}/redact`) and retention policy execution (`POST /retention/apply`).
  - **BOLA Protection**: `GET /api/v1/audit/export` is explicitly restricted to `ROLE_AUDITOR` and `ROLE_ADMIN`. Ingest-only role attempts return HTTP 403 Forbidden.
- **Resource Level Authorization (BOLA/IDOR)**: `validateResourceAuthorization()` in `AuditLogController.java` enforces that non-auditors can only query audit records matching their authenticated principal. Cross-actor queries throw `AuditSecurityException` returning HTTP 403 Forbidden.

## 4. Stateless Threat Model & CSRF/CORS Policy
- **CSRF**: Disabled intentionally because the API is strictly stateless (`SessionCreationPolicy.STATELESS`) and uses HTTP Basic / Header authentication rather than ambient browser session cookies.
- **CORS**: Enforces restricted allowed origins configured via `${schwab.cors.allowed-origins}`. No wildcard `*` with credentials allowed.

## 5. Environment & Operational Guardrails
- **Production Profile Isolation**: `application-prod.properties` explicitly disables H2 console (`spring.h2.console.enabled=false`) and mandates PostgreSQL dialect.
- **Actuator Health Endpoint**: `spring-boot-starter-actuator` included for `/actuator/health` operational monitoring.
- **PostgreSQL Driver**: `org.postgresql:postgresql:42.7.3` included in `build.gradle`.

## 6. Architectural Note: Non-Repudiation & Signing Protocols
- HMAC-SHA256 signatures provide keyed integrity and proof of origin between trusted symmetrical parties. For third-party regulatory verification without key sharing, asymmetric digital signatures (RSA-PSS or ECDSA-P256) with PKI certificate chain verification are recommended.
