package com.schwab.auditlog.repository;

import com.schwab.auditlog.model.AuditRecord;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface AuditRecordRepository extends JpaRepository<AuditRecord, Long>, JpaSpecificationExecutor<AuditRecord> {

    Optional<AuditRecord> findTopByOrderBySequenceNumberDesc();

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT a FROM AuditRecord a WHERE a.sequenceNumber = (SELECT MAX(b.sequenceNumber) FROM AuditRecord b)")
    Optional<AuditRecord> findLatestRecordForUpdate();

    Optional<AuditRecord> findBySequenceNumber(Long sequenceNumber);

    List<AuditRecord> findAllByOrderBySequenceNumberAsc();

    @Query("SELECT MAX(a.sequenceNumber) FROM AuditRecord a")
    Long findMaxSequenceNumber();
}
