package com.schwab.auditlog.repository;

import com.schwab.auditlog.model.ChainCheckpoint;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface ChainCheckpointRepository extends JpaRepository<ChainCheckpoint, Long> {
    Optional<ChainCheckpoint> findTopByOrderByHeadSequenceNumberDesc();
    Optional<ChainCheckpoint> findByCheckpointId(String checkpointId);
}
