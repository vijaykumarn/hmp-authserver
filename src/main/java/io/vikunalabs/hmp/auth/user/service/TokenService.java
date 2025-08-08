package io.vikunalabs.hmp.auth.user.service;

import io.vikunalabs.hmp.auth.user.domain.Token;
import io.vikunalabs.hmp.auth.user.domain.TokenType;
import io.vikunalabs.hmp.auth.user.domain.User;
import java.util.UUID;

public interface TokenService {
    Token findValidToken(UUID tokenValue, TokenType tokenType);

    Token createToken(Long userId, TokenType tokenType);

    Token confirmToken(UUID tokenValue, TokenType tokenType);

    void revokePendingTokens(User user, TokenType tokenType);

    boolean hasRecentTokenRequest(String email, TokenType tokenType, int minutes);

    void cleanupExpiredTokens();
}
