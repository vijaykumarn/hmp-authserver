package io.vikunalabs.hmp.auth.shared.config;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@ConfigurationProperties(prefix = "app.rate-limit")
@Component
public class RateLimitProperties {
    private RateLimit login = new RateLimit(5, 15);
    private RateLimit resendVerification = new RateLimit(3, 5);
    private RateLimit forgotPassword = new RateLimit(3, 5);

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class RateLimit {
        private int attempts;
        private int windowMinutes;
    }
}
