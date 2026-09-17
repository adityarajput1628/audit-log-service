package com.schwab.auditlog.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RedactFieldRequest {

    @NotBlank(message = "fieldPath is required (e.g., 'accountNumber', 'ssn', 'user.email')")
    private String fieldPath;

    @NotBlank(message = "reason is required for compliance audit trails")
    private String reason;
}
