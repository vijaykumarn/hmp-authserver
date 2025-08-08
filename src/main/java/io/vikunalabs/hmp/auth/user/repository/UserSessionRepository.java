package io.vikunalabs.hmp.auth.user.repository;

import io.vikunalabs.hmp.auth.user.domain.LogoutReason;
import io.vikunalabs.hmp.auth.user.domain.UserSession;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface UserSessionRepository extends JpaRepository<UserSession, Long> {

    Optional<UserSession> findBySessionIdAndActiveTrue(String sessionId);

    @Query("SELECT s FROM UserSession s WHERE s.user.id = :userId AND s.active = true ORDER BY s.createdAt DESC")
    List<UserSession> findActiveSessionsByUserId(@Param("userId") Long userId);

    @Query("SELECT s FROM UserSession s WHERE s.user.id = :userId AND s.active = true ORDER BY s.createdAt ASC")
    List<UserSession> findActiveSessionsByUserIdOrderByCreatedAsc(@Param("userId") Long userId);

    @Query("SELECT COUNT(s) FROM UserSession s WHERE s.user.id = :userId AND s.active = true")
    long countActiveSessionsByUserId(@Param("userId") Long userId);

    @Query("SELECT s FROM UserSession s WHERE s.expiresAt < :now AND s.active = true")
    List<UserSession> findExpiredSessions(@Param("now") Instant now);

    @Query("SELECT s FROM UserSession s WHERE s.lastAccessedAt < :cutoff AND s.active = true")
    List<UserSession> findInactiveSessions(@Param("cutoff") Instant cutoff);

    @Modifying
    @Query(
            "UPDATE UserSession s SET s.active = false, s.logoutReason = :reason WHERE s.user.id = :userId AND s.active = true")
    int invalidateAllUserSessions(@Param("userId") Long userId, @Param("reason") LogoutReason reason);

    @Modifying
    @Query(
            "UPDATE UserSession s SET s.active = false, s.logoutReason = 'SESSION_EXPIRED' WHERE s.expiresAt < :now AND s.active = true")
    int markExpiredSessions(@Param("now") Instant now);

    @Query("SELECT s FROM UserSession s WHERE s.user.id = :userId AND s.ipAddress = :ipAddress AND s.active = true")
    List<UserSession> findActiveSessionsByUserAndIp(@Param("userId") Long userId, @Param("ipAddress") String ipAddress);
}
