package io.vikunalabs.hmp.auth.user.service.impl;

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

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

@Slf4j
@RequiredArgsConstructor
@Service
public class TokenServiceImpl implements TokenService {

    private final TokenRepository tokenRepository;
    private final UserAccountService accountService;

    @Override
    public Token findValidToken(UUID tokenValue, TokenType tokenType) {
        return tokenRepository.findByValue(tokenValue)
                .filter(token -> token.getTokenType() == tokenType && token.isValid())
                .orElseThrow(() -> TokenNotFoundException.withToken(tokenValue.toString()));
    }

    @Override
    public Token createToken(Long userId, TokenType tokenType) {
        UserAccount userAccount = accountService.getUserAccountReference(userId);

        // Revoke any existing pending tokens for this user and type
        revokePendingTokens(userAccount, tokenType);

        Token token = new Token(userAccount, tokenType, Instant.now().plus(1, ChronoUnit.HOURS));
        return tokenRepository.save(token);
    }

    @Override
    public Token confirmToken(UUID tokenValue, TokenType tokenType) {
        Token token = findValidToken(tokenValue, tokenType);
        token.confirm();
        return tokenRepository.save(token);
    }

    @Override
    public void revokePendingTokens(UserAccount userAccount, TokenType tokenType) {
        List<Token> pendingTokens = tokenRepository
                .findByUserAccountAndTokenTypeAndStatus(userAccount, tokenType, TokenStatus.PENDING);

        pendingTokens.forEach(Token::revoke);
        tokenRepository.saveAll(pendingTokens);
    }

    @Override
    public boolean hasRecentTokenRequest(String email, TokenType tokenType, int minutes) {
        Instant since = Instant.now().minus(minutes, ChronoUnit.MINUTES);
        long count = tokenRepository.countRecentTokensByEmailAndType(email, tokenType, since);
        return count > 0;
    }

}
