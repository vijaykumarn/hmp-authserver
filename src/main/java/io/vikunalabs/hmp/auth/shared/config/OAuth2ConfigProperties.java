package io.vikunalabs.hmp.auth.shared.config;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import java.util.List;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

@Data
@ConfigurationProperties(prefix = "app.oauth2")
@Component
@Validated
public class OAuth2ConfigProperties {

    @NotBlank private String successRedirectUrl = "http://localhost:5173/dashboard";

    @NotBlank private String failureRedirectUrl = "http://localhost:5173/login";

    @NotNull private RateLimit rateLimit = new RateLimit();

    @NotNull private Security security = new Security();

    @NotNull private List<String> allowedProviders = List.of("google");

    private boolean enabled = true;

    @Data
    public static class RateLimit {
        @Positive private int maxAttemptsPerIp = 10;

        @Positive private int maxAttemptsPerEmail = 5;

        @Positive private int windowMinutes = 15;

        @Positive private int emailWindowMinutes = 30;
    }

    @Data
    public static class Security {
        private boolean csrfEnabled = true;
        private boolean stateValidationEnabled = true;
        private boolean auditLoggingEnabled = true;
        private boolean requireEmailVerified = true;

        @Positive private int sessionTimeoutSeconds = 3600;

        @Positive private int maxConcurrentSessions = 3;
    }
}
