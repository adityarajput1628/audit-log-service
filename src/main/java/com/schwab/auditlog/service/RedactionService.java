package com.schwab.auditlog.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.schwab.auditlog.crypto.HashChainEngine;
import com.schwab.auditlog.crypto.HashChainEngine.RedactionEntry;
import com.schwab.auditlog.dto.RedactFieldRequest;
import com.schwab.auditlog.model.AuditRecord;
import com.schwab.auditlog.repository.AuditRecordRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

@Service
public class RedactionService {

    private final AuditRecordRepository repository;
    private final HashChainEngine hashChainEngine;
    private final ObjectMapper objectMapper;

    public RedactionService(AuditRecordRepository repository, HashChainEngine hashChainEngine, ObjectMapper objectMapper) {
        this.repository = repository;
        this.hashChainEngine = hashChainEngine;
        this.objectMapper = objectMapper;
    }

    /**
     * Performs structured redaction on sensitive payload fields without breaking cryptographic hash chain.
     */
    @Transactional
    @SuppressWarnings("unchecked")
    public AuditRecord redactPayloadField(Long recordId, RedactFieldRequest request) {
        AuditRecord record = repository.findById(recordId)
                .orElseThrow(() -> new IllegalArgumentException("Audit record not found with ID: " + recordId));

        if (record.isArchived()) {
            throw new IllegalStateException("Cannot redact fields on an archived record.");
        }

        try {
            Map<String, Object> payloadMap = objectMapper.readValue(record.getPayloadJson(), new TypeReference<>() {});
            Map<String, RedactionEntry> redactionsMap = new HashMap<>();

            if (record.getRedactionsJson() != null && !record.getRedactionsJson().trim().isEmpty()) {
                redactionsMap = objectMapper.readValue(record.getRedactionsJson(), new TypeReference<>() {});
            }

            String fieldPath = request.getFieldPath();
            String salt = record.getPreviousHash() != null ? record.getPreviousHash() : "SCHWAB_SALT";

            Object rawValue = extractAndRedactField(payloadMap, fieldPath, "");

            if (rawValue == null) {
                throw new IllegalArgumentException("Field path '" + fieldPath + "' not found in payload.");
            }

            // Calculate salted field hash using record's salt
            String fieldHash = hashChainEngine.hashFieldValue(rawValue, salt);
            redactionsMap.put(fieldPath, new RedactionEntry(salt, fieldHash));

            record.setPayloadJson(objectMapper.writeValueAsString(payloadMap));
            record.setRedactionsJson(objectMapper.writeValueAsString(redactionsMap));

            // Save redacted record
            AuditRecord updatedRecord = repository.save(record);

            // Verify hash chain stability post-redaction
            String recomputedHash = hashChainEngine.calculateRecordHash(updatedRecord);
            if (!recomputedHash.equalsIgnoreCase(updatedRecord.getRecordHash())) {
                throw new IllegalStateException("CRITICAL BUG: Redaction altered calculated hash! Original: " 
                        + updatedRecord.getRecordHash() + " Recomputed: " + recomputedHash);
            }

            return updatedRecord;
        } catch (Exception e) {
            if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            }
            throw new RuntimeException("Failed to execute structured redaction: " + e.getMessage(), e);
        }
    }

    @SuppressWarnings("unchecked")
    private Object extractAndRedactField(Map<String, Object> map, String targetPath, String currentPath) {
        String[] parts = targetPath.split("\\.", 2);
        String currentKey = parts[0];

        if (!map.containsKey(currentKey)) {
            return null;
        }

        if (parts.length == 1) {
            Object rawVal = map.get(currentKey);
            map.put(currentKey, "[REDACTED]");
            return rawVal;
        } else {
            Object subObj = map.get(currentKey);
            if (subObj instanceof Map) {
                return extractAndRedactField((Map<String, Object>) subObj, parts[1], currentPath.isEmpty() ? currentKey : currentPath + "." + currentKey);
            }
        }
        return null;
    }
}
