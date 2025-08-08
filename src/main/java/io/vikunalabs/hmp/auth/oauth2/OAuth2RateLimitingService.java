package io.vikunalabs.hmp.auth.oauth2;

import io.vikunalabs.hmp.auth.shared.exception.TooManyRequestsException;
import io.vikunalabs.hmp.auth.shared.security.RateLimitingService;
import java.time.Duration;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@RequiredArgsConstructor
@Service
public class OAuth2RateLimitingService {

    private final RateLimitingService rateLimitingService;

    public void checkOAuth2AttemptLimit(String clientIp, String email) {
        String rateLimitKey = "oauth2-attempt:" + clientIp;

        if (rateLimitingService.isRateLimited(rateLimitKey, 10, Duration.ofMinutes(15))) {
            log.warn("OAuth2 rate limit exceeded for IP: {}", clientIp);
            throw new TooManyRequestsException("Too many OAuth2 sign-in attempts. Please try again later.");
        }
    }

    public void checkOAuth2EmailLimit(String email) {
        String emailRateLimitKey = "oauth2-email:" + email;

        if (rateLimitingService.isRateLimited(emailRateLimitKey, 5, Duration.ofMinutes(30))) {
            log.warn("OAuth2 rate limit exceeded for email: {}", email);
            throw new TooManyRequestsException("Too many OAuth2 attempts for this email. Please try again later.");
        }
    }

    public void clearOAuth2RateLimit(String clientIp, String email) {
        rateLimitingService.clearRateLimit("oauth2-attempt:" + clientIp);
        rateLimitingService.clearRateLimit("oauth2-email:" + email);
    }
}
