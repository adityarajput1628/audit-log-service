# Scenario A Breakdown – Greenfield: Core Audit Log Service

## 1. Task Decomposition & Sequencing
- **Task A.1**: Define Java domain models (`AuditRecord`), request/response DTOs, and Spring Data JPA repositories.
- **Task A.2**: Build canonical serialization & SHA-256 hash engine (`HashChainEngine`).
- **Task A.3**: Build append-only event ingestion write API (`POST /api/v1/audit/events`).
- **Task A.4**: Build multi-criteria query API with JPA Specification pagination (`GET /api/v1/audit/events`).
- **Task A.5**: Build full chain verification engine (`GET /api/v1/audit/verify`) flagging sequence gaps, hash mismatches, and chain link breaks.
- **Task A.6**: Implement direct database tamper simulator for live reviewer testing (`POST /api/v1/audit/tamper-test`).

---

## 2. Technical Decisions & Trade-Offs

### Timestamp Assignment
- **Choice**: Server-assigned timestamp (`Instant.now()`) by default, with caller-override option.
- **Rationale**: Server timestamping prevents clock skew anomalies and guarantees chronological consistency across distributed clients.

### Verification Strategy
- **Choice**: Sequential walk from Genesis node to HEAD.
- **Trade-off**: $O(N)$ verification cost for full chain. For high-volume production, checkpointing / Merkle tree root anchoring can be introduced.

---

## 3. Validation & Verification
- Unit & integration tests in `AuditLogServiceTest.java`.
- Verified that appending records produces valid SHA-256 hashes linked to prior records.
- Verified that corrupting a record via direct database update triggers `HASH_MISMATCH` violation on the exact altered sequence index.
