package io.vikunalabs.hmp.auth.shared.security;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class RateLimitingService {

    // Simple in-memory rate limiting (for production, use Redis)
    private final Map<String, RateLimitInfo> rateLimitMap = new ConcurrentHashMap<>();

    public boolean isRateLimited(String identifier, int maxAttempts, Duration timeWindow) {
        rateLimitMap
                .entrySet()
                .removeIf(entry ->
                        entry.getValue().getFirstAttempt().plus(timeWindow).isBefore(Instant.now()));

        RateLimitInfo info =
                rateLimitMap.computeIfAbsent(identifier, k -> new RateLimitInfo(0, Instant.now(), Instant.now()));

        Instant now = Instant.now();

        // Reset if outside time window
        if (info.getFirstAttempt().plus(timeWindow).isBefore(now)) {
            info.setAttempts(1);
            info.setFirstAttempt(now);
            info.setLastAttempt(now);
            return false;
        }

        // Increment attempts
        info.setAttempts(info.getAttempts() + 1);
        info.setLastAttempt(now);

        boolean limited = info.getAttempts() > maxAttempts;
        if (limited) {
            log.warn("Rate limit exceeded for identifier: {} (attempts: {})", identifier, info.getAttempts());
        }

        return limited;
    }

    public void clearRateLimit(String identifier) {
        rateLimitMap.remove(identifier);
        log.debug("Cleared rate limit for identifier: {}", identifier);
    }

    @Data
    @AllArgsConstructor
    private static class RateLimitInfo {
        private int attempts;
        private Instant firstAttempt;
        private Instant lastAttempt;
    }
}
