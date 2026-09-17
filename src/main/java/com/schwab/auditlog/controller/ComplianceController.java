package com.schwab.auditlog.controller;

import com.schwab.auditlog.dto.ComplianceReport;
import com.schwab.auditlog.service.ComplianceService;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;

@RestController
@RequestMapping("/api/v1/compliance")
@CrossOrigin(origins = "*")
public class ComplianceController {

    private final ComplianceService complianceService;

    public ComplianceController(ComplianceService complianceService) {
        this.complianceService = complianceService;
    }

    /**
     * Scenario C: Regulatory Client Account Access Compliance Report.
     */
    @GetMapping("/client-access-report")
    public ResponseEntity<ComplianceReport> getClientAccessReport(
            @RequestParam String clientAccountId,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to
    ) {
        ComplianceReport report = complianceService.generateClientAccessReport(clientAccountId, from, to);
        return ResponseEntity.ok(report);
    }
}
