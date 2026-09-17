# Scenario B Breakdown – Retention, Redaction & Bulk Export

## 1. Zero-Knowledge Structured Redaction
- **Engineering Challenge**: Redacting PII (e.g. account numbers, SSNs) changes raw payload text, which would naturally break the original SHA-256 hash.
- **Solution**: Zero-Knowledge Salted Field Hash Preservation.
  1. Extract raw field value prior to redaction.
  2. Generate secure random salt (`UUID.randomUUID()`).
  3. Compute salted field hash $\text{SHA256}(\text{value} \parallel \text{salt})$.
  4. Store `{ "salt": salt, "fieldHash": fieldHash }` in record's `redactions_json` metadata.
  5. Replace payload field value with string `"[REDACTED]"`.
  6. When calculating record hash during verification, `HashChainEngine` substitutes `fieldHash` for `"[REDACTED]"`, producing **the exact original record hash**.
- **Outcome**: 100% data privacy compliance (GDPR/CCPA) with zero hash chain corruption.

---

## 2. Policy-Based Retention
- **Engineering Challenge**: Deleting old audit records breaks sequential hash chaining.
- **Solution**: Verifiable Tombstone Archiving.
  - Records older than $N$ days are marked `archived = true` with `archived_at` timestamp.
  - Payload is converted to a minimal tombstone summary (`_archived: true`), while sequence number, event type, actor ID, timestamp, previous hash, and record hash are preserved.
- **Outcome**: `/api/v1/audit/verify` verifies archived tombstones without false-positive chain breaks.

---

## 3. Self-Contained Verifiable Bulk Export
- `GET /api/v1/audit/export?resourceId=X`: Generates JSON export bundle containing:
  - List of audit records for resource.
  - Overall `exportDigest` (SHA-256 digest of concatenated record hashes).
  - `chainGenesisHash` and `chainLatestHash` for independent recipient validation.
  - `verificationStatus: "VERIFIED_INTACT"`.
