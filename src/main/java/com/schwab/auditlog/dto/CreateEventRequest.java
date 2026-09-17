package com.schwab.auditlog.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.*;

import java.time.Instant;
import java.util.Map;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CreateEventRequest {

    @NotBlank(message = "eventType is required")
    private String eventType;

    @NotBlank(message = "actorId is required")
    private String actorId;

    @NotBlank(message = "resourceType is required")
    private String resourceType;

    @NotBlank(message = "resourceId is required")
    private String resourceId;

    @NotNull(message = "payload is required")
    private Map<String, Object> payload;

    /**
     * Optional caller-supplied timestamp.
     * If null, server assigns Instant.now() to maintain strict chronological order.
     */
    private Instant timestamp;
}
