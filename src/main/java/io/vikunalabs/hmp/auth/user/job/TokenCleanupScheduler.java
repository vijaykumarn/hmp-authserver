package io.vikunalabs.hmp.auth.user.job;

import io.vikunalabs.hmp.auth.user.service.TokenService;
import io.vikunalabs.hmp.auth.user.service.impl.TokenServiceImpl;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Slf4j
@RequiredArgsConstructor
@Component
public class TokenCleanupScheduler {

    private final TokenService tokenService; // Note: using impl for cleanup method

    // Run every hour to cleanup expired tokens
    @Scheduled(fixedRate = 3600000) // 1 hour
    public void cleanupExpiredTokens() {
        log.info("Starting cleanup of expired tokens");
        try {
            tokenService.cleanupExpiredTokens();
            log.info("Completed cleanup of expired tokens");
        } catch (Exception e) {
            log.error("Error during token cleanup", e);
        }
    }
}