package io.vikunalabs.hmp.auth.user.service.impl;

import io.vikunalabs.hmp.auth.shared.exception.TokenExpiredException;
import io.vikunalabs.hmp.auth.shared.exception.TokenNotFoundException;
import io.vikunalabs.hmp.auth.user.domain.Token;
import io.vikunalabs.hmp.auth.user.domain.TokenStatus;
import io.vikunalabs.hmp.auth.user.domain.TokenType;
import io.vikunalabs.hmp.auth.user.domain.UserAccount;
import io.vikunalabs.hmp.auth.user.repository.TokenRepository;
import io.vikunalabs.hmp.auth.user.service.TokenService;
import io.vikunalabs.hmp.auth.user.service.UserAccountService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

@Slf4j
@RequiredArgsConstructor
@Service
@Transactional(readOnly = true)
public class TokenServiceImpl implements TokenService {

    private final TokenRepository tokenRepository;
    private final UserAccountService accountService;

    @Override
    public Token findValidToken(UUID tokenValue, TokenType tokenType) {
        Token token = tokenRepository.findByValue(tokenValue)
                .filter(t -> t.getTokenType() == tokenType)
                .orElseThrow(() -> {
                    log.warn("Token not found: {}", tokenValue);
                    return TokenNotFoundException.withToken(tokenValue.toString());
                });

        if (token.isExpired()) {
            log.warn("Token expired: {}", tokenValue);
            throw TokenExpiredException.withToken(tokenValue.toString());
        }

        if (token.getStatus() != TokenStatus.PENDING) {
            log.warn("Token not in pending status: {} - current status: {}", tokenValue, token.getStatus());
            throw TokenNotFoundException.withToken(tokenValue.toString());
        }

        return token;
    }

    @Override
    @Transactional
    public Token createToken(Long userId, TokenType tokenType) {
        log.debug("Creating {} token for user ID: {}", tokenType, userId);

        UserAccount userAccount = accountService.getUserAccountReference(userId);

        // Revoke any existing pending tokens for this user and type
        revokePendingTokens(userAccount, tokenType);

        // Create new token with 1-hour expiry
        Instant expiresAt = Instant.now().plus(1, ChronoUnit.HOURS);
        Token token = new Token(userAccount, tokenType, expiresAt);

        Token savedToken = tokenRepository.save(token);
        log.info("Created {} token for user ID: {} with expiry: {}",
                tokenType, userId, expiresAt);

        return savedToken;
    }

    @Override
    @Transactional
    public Token confirmToken(UUID tokenValue, TokenType tokenType) {
        log.debug("Confirming {} token: {}", tokenType, tokenValue);

        Token token = findValidToken(tokenValue, tokenType);
        token.confirm();

        Token confirmedToken = tokenRepository.save(token);
        log.info("Confirmed {} token for user ID: {}", tokenType, token.getUserAccount().getId());

        return confirmedToken;
    }

    @Override
    @Transactional
    public void revokePendingTokens(UserAccount userAccount, TokenType tokenType) {
        List<Token> pendingTokens = tokenRepository
                .findByUserAccountAndTokenTypeAndStatus(userAccount, tokenType, TokenStatus.PENDING);

        if (!pendingTokens.isEmpty()) {
            log.debug("Revoking {} pending {} tokens for user ID: {}",
                    pendingTokens.size(), tokenType, userAccount.getId());
            pendingTokens.forEach(Token::revoke);
            tokenRepository.saveAll(pendingTokens);
        }
    }

    @Override
    public boolean hasRecentTokenRequest(String email, TokenType tokenType, int minutes) {
        Instant since = Instant.now().minus(minutes, ChronoUnit.MINUTES);
        long count = tokenRepository.countRecentTokensByEmailAndType(email, tokenType, since);

        log.debug("Found {} recent {} token requests for email: {} since: {}",
                count, tokenType, email, since);

        return count > 0;
    }

    // Additional method for cleanup job
    @Transactional
    public void cleanupExpiredTokens() {
        List<Token> expiredTokens = tokenRepository.findExpiredTokens(Instant.now());
        if (!expiredTokens.isEmpty()) {
            log.info("Cleaning up {} expired tokens", expiredTokens.size());
            expiredTokens.forEach(token -> token.setStatus(TokenStatus.EXPIRED));
            tokenRepository.saveAll(expiredTokens);
        }
    }
}
