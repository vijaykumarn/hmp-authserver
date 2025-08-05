package io.vikunalabs.hmp.auth.user.repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import io.vikunalabs.hmp.auth.user.domain.UserAccount;
import io.vikunalabs.hmp.auth.user.domain.UserExistsDTO;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface UserAccountRepository extends JpaRepository<UserAccount, Long> {
    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

    Optional<UserAccount> findByEmail(String email);

    Optional<UserExistsDTO> findByUsernameOrEmail(String username, String email);

    @Query("SELECT u FROM UserAccount u WHERE u.emailVerified = false AND u.userProfile.createdAt < :cutoffTime")
    List<UserAccount> findUnverifiedAccountsOlderThan(@Param("cutoffTime") Instant cutoffTime);
}
