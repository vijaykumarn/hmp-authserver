package io.vikunalabs.hmp.auth.user.job;

import io.vikunalabs.hmp.auth.user.service.SessionService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Slf4j
@RequiredArgsConstructor
@Component
public class SessionCleanupScheduler {

    private final SessionService sessionService;

    // Run every hour to cleanup expired sessions
    @Scheduled(fixedRate = 3600000) // 1 hour
    public void cleanupExpiredSessions() {
        log.info("Starting cleanup of expired sessions");
        try {
            sessionService.cleanupExpiredSessions();
            log.info("Completed cleanup of expired sessions");
        } catch (Exception e) {
            log.error("Error during session cleanup", e);
        }
    }
}