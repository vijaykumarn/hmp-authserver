package io.vikunalabs.hmp.auth.user.repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import io.vikunalabs.hmp.auth.user.domain.Token;
import io.vikunalabs.hmp.auth.user.domain.TokenStatus;
import io.vikunalabs.hmp.auth.user.domain.TokenType;
import io.vikunalabs.hmp.auth.user.domain.UserAccount;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface TokenRepository extends JpaRepository<Token, Long> {
    Optional<Token> findByValue(UUID token);

    boolean existsByUserAccountIdAndStatus(Long userAccountId, TokenStatus status);

    @Query("SELECT t FROM Token t WHERE t.userAccount = :userAccount AND t.tokenType = :tokenType AND t.status = :status")
    List<Token> findByUserAccountAndTokenTypeAndStatus(
            @Param("userAccount") UserAccount userAccount,
            @Param("tokenType") TokenType tokenType,
            @Param("status") TokenStatus status
    );

    @Query("SELECT t FROM Token t WHERE t.expiresAt < :now")
    List<Token> findExpiredTokens(@Param("now") Instant now);

    @Query("SELECT COUNT(t) FROM Token t WHERE t.userAccount.email = :email AND t.tokenType = :tokenType AND t.createdAt > :since")
    long countRecentTokensByEmailAndType(
            @Param("email") String email,
            @Param("tokenType") TokenType tokenType,
            @Param("since") Instant since
    );
}
