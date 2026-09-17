package com.schwab.auditlog.dto;

import jakarta.validation.constraints.Min;
import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RetentionRequest {

    @Min(value = 1, message = "retentionWindowDays must be at least 1 day")
    private int retentionWindowDays;

    private boolean dryRun;
}
