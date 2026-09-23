package com.schwab.auditlog.exception;

public class AuditSecurityException extends RuntimeException {

    public AuditSecurityException(String message) {
        super(message);
    }

    public AuditSecurityException(String message, Throwable cause) {
        super(message, cause);
    }
}
