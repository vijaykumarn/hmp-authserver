package io.vikunalabs.hmp.auth.oauth2.service;

import io.vikunalabs.hmp.auth.shared.config.OAuth2ConfigProperties;
import io.vikunalabs.hmp.auth.shared.exception.TooManyRequestsException;
import io.vikunalabs.hmp.auth.shared.security.RateLimitingService;
import java.time.Duration;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

// 4. Enhanced Rate Limiting with Progressive Backoff
@Slf4j
@RequiredArgsConstructor
@Service
public class OAuth2RateLimitingService {

    private final RateLimitingService rateLimitingService;
    private final OAuth2ConfigProperties config;

    public void checkOAuth2AttemptLimit(String clientIp, String email) {
        OAuth2ConfigProperties.RateLimit rateLimit = config.getRateLimit();
        String rateLimitKey = "oauth2-attempt:" + clientIp;

        if (rateLimitingService.isRateLimited(
                rateLimitKey, rateLimit.getMaxAttemptsPerIp(), Duration.ofMinutes(rateLimit.getWindowMinutes()))) {

            log.warn("OAuth2 rate limit exceeded for IP: {}", clientIp);

            if (rateLimit.isProgressiveBackoffEnabled()) {
                int backoffMinutes = calculateProgressiveBackoff(clientIp);
                throw new TooManyRequestsException(String.format(
                        "Too many OAuth2 sign-in attempts. Please try again in %d minutes.", backoffMinutes));
            } else {
                throw new TooManyRequestsException("Too many OAuth2 sign-in attempts. Please try again later.");
            }
        }
    }

    private int calculateProgressiveBackoff(String clientIp) {
        // Get attempt count and calculate progressive backoff
        OAuth2ConfigProperties.RateLimit rateLimit = config.getRateLimit();
        // Implementation would track attempt counts and increase backoff time
        return Math.min(rateLimit.getBaseBackoffMinutes() * 2, rateLimit.getMaxBackoffMinutes());
    }

    public void checkOAuth2EmailLimit(String email) {
        OAuth2ConfigProperties.RateLimit rateLimit = config.getRateLimit();
        String emailRateLimitKey = "oauth2-email:" + email;

        if (rateLimitingService.isRateLimited(
                emailRateLimitKey,
                rateLimit.getMaxAttemptsPerEmail(),
                Duration.ofMinutes(rateLimit.getEmailWindowMinutes()))) {

            log.warn("OAuth2 rate limit exceeded for email: {}", email);
            throw new TooManyRequestsException("Too many OAuth2 attempts for this email. Please try again later.");
        }
    }

    public void clearOAuth2RateLimit(String clientIp, String email) {
        rateLimitingService.clearRateLimit("oauth2-attempt:" + clientIp);
        rateLimitingService.clearRateLimit("oauth2-email:" + email);
    }
}
