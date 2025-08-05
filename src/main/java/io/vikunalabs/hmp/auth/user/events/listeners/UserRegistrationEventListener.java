package io.vikunalabs.hmp.auth.user.events.listeners;

import io.vikunalabs.hmp.auth.user.domain.Token;
import io.vikunalabs.hmp.auth.user.domain.TokenType;
import io.vikunalabs.hmp.auth.user.events.UserRegistrationEvent;
import io.vikunalabs.hmp.auth.user.service.TokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

@Slf4j
@RequiredArgsConstructor
@Component
public class UserRegistrationEventListener {

    private final TokenService tokenService;

    @Value("${app.confirmation.url}")
    private String confirmationUrl;

    @Async
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void handleUserRegistrationEvent(UserRegistrationEvent event) {
        Long userId = event.userProfileId();
        log.info("Processing registration event for user {}", userId);
        Token token = tokenService.createToken(userId, TokenType.EMAIL_VERIFICATION);
        String confirmationLink = String.format("%s?token=%s", confirmationUrl, token.getValue());
        log.info("Generated confirmation link for user {}: {}", userId, confirmationLink);

        // send email
    }
}
