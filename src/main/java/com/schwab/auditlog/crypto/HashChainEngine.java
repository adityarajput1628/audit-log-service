package com.schwab.auditlog.crypto;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.schwab.auditlog.model.AuditRecord;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Component
public class HashChainEngine {

    private final ObjectMapper objectMapper;

    public HashChainEngine() {
        this.objectMapper = new ObjectMapper();
        this.objectMapper.configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true);
        this.objectMapper.configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);
    }

    /**
     * Computes the SHA-256 record hash for an AuditRecord.
     */
    public String calculateRecordHash(AuditRecord record) {
        String payloadHash = calculatePayloadHash(record.getPayloadJson(), record.getRedactionsJson(), record.getPreviousHash());
        String timestampIso = record.getTimestamp().truncatedTo(ChronoUnit.MILLIS).toString();
        
        String canonicalString = String.join("|",
                String.valueOf(record.getSequenceNumber()),
                record.getEventType(),
                record.getActorId(),
                record.getResourceType(),
                record.getResourceId(),
                payloadHash,
                timestampIso,
                record.getPreviousHash()
        );

        return sha256Hex(canonicalString);
    }

    /**
     * Computes payload hash. If redaction metadata exists, handles redacted field hashes.
     */
    public String calculatePayloadHash(String payloadJson, String redactionsJson, String recordSalt) {
        if (payloadJson == null || payloadJson.trim().isEmpty()) {
            return sha256Hex("{}");
        }

        try {
            Map<String, RedactionEntry> redactionsMap = new HashMap<>();
            if (redactionsJson != null && !redactionsJson.trim().isEmpty()) {
                redactionsMap = objectMapper.readValue(redactionsJson, new TypeReference<Map<String, RedactionEntry>>() {});
            }

            if (redactionsMap.containsKey("_ARCHIVED_PAYLOAD")) {
                return redactionsMap.get("_ARCHIVED_PAYLOAD").getFieldHash();
            }

            Map<String, Object> payloadMap = objectMapper.readValue(payloadJson, new TypeReference<>() {});
            String salt = (recordSalt != null && !recordSalt.isEmpty()) ? recordSalt : "SCHWAB_SALT";
            Map<String, Object> normalizedMap = normalizePayloadForHash(payloadMap, redactionsMap, "", salt);
            String canonicalJson = objectMapper.writeValueAsString(normalizedMap);
            return sha256Hex(canonicalJson);
        } catch (Exception e) {
            return sha256Hex(payloadJson);
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> normalizePayloadForHash(Map<String, Object> map, Map<String, RedactionEntry> redactionMap, String parentPath, String salt) {
        Map<String, Object> result = new TreeMap<>();
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            String key = entry.getKey();
            Object val = entry.getValue();
            String currentPath = parentPath.isEmpty() ? key : parentPath + "." + key;

            if (redactionMap.containsKey(currentPath) && "[REDACTED]".equals(val)) {
                // Use preserved field hash
                result.put(key, redactionMap.get(currentPath).getFieldHash());
            } else if (val instanceof Map) {
                result.put(key, normalizePayloadForHash((Map<String, Object>) val, redactionMap, currentPath, salt));
            } else {
                // Compute field hash using field salt
                String fieldSalt = redactionMap.containsKey(currentPath) ? redactionMap.get(currentPath).getSalt() : salt;
                result.put(key, hashFieldValue(val, fieldSalt));
            }
        }
        return result;
    }

    /**
     * Computes field hash with salt for zero-knowledge redaction verification.
     */
    public String hashFieldValue(Object value, String salt) {
        String valStr = value == null ? "null" : value.toString();
        return sha256Hex(valStr + ":" + salt);
    }

    /**
     * HMAC-SHA256 helper method for keyed proof signatures and non-repudiation.
     */
    public String hmacSha256(String input, String secretKey) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            javax.crypto.spec.SecretKeySpec secretKeySpec = new javax.crypto.spec.SecretKeySpec(
                    (secretKey != null ? secretKey : "SCHWAB_HMAC_KEY").getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(secretKeySpec);
            byte[] hash = mac.doFinal(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder(2 * hash.length);
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute HMAC-SHA256", e);
        }
    }

    /**
     * SHA-256 helper method.
     */
    public String sha256Hex(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder(2 * hash.length);
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }

    public static class RedactionEntry {
        private String salt;
        private String fieldHash;

        public RedactionEntry() {}

        public RedactionEntry(String salt, String fieldHash) {
            this.salt = salt;
            this.fieldHash = fieldHash;
        }

        public String getSalt() { return salt; }
        public void setSalt(String salt) { this.salt = salt; }

        public String getFieldHash() { return fieldHash; }
        public void setFieldHash(String fieldHash) { this.fieldHash = fieldHash; }
    }
}
