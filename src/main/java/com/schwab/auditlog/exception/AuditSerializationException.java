package com.schwab.auditlog.exception;

public class AuditSerializationException extends RuntimeException {

    public AuditSerializationException(String message) {
        super(message);
    }

    public AuditSerializationException(String message, Throwable cause) {
        super(message, cause);
    }
}
