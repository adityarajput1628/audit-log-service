package com.schwab.auditlog.repository;

import com.schwab.auditlog.model.AuditRecord;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface AuditRecordRepository extends JpaRepository<AuditRecord, Long>, JpaSpecificationExecutor<AuditRecord> {

    Optional<AuditRecord> findTopByOrderBySequenceNumberDesc();

    Optional<AuditRecord> findBySequenceNumber(Long sequenceNumber);

    List<AuditRecord> findAllByOrderBySequenceNumberAsc();

    @Query("SELECT MAX(a.sequenceNumber) FROM AuditRecord a")
    Long findMaxSequenceNumber();
}
