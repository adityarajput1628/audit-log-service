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
    @jakarta.validation.constraints.Size(max = 255, message = "eventType cannot exceed 255 characters")
    private String eventType;

    @NotBlank(message = "actorId is required")
    @jakarta.validation.constraints.Size(max = 255, message = "actorId cannot exceed 255 characters")
    private String actorId;

    @NotBlank(message = "resourceType is required")
    @jakarta.validation.constraints.Size(max = 255, message = "resourceType cannot exceed 255 characters")
    private String resourceType;

    @NotBlank(message = "resourceId is required")
    @jakarta.validation.constraints.Size(max = 255, message = "resourceId cannot exceed 255 characters")
    private String resourceId;

    @NotNull(message = "payload is required")
    private Map<String, Object> payload;

    /**
     * Optional caller-supplied timestamp.
     * If null, server assigns Instant.now() to maintain strict chronological order.
     */
    private Instant timestamp;
}
