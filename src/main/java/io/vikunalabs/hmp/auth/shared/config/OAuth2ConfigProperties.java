package io.vikunalabs.hmp.auth.shared.config;

import jakarta.annotation.PostConstruct;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import java.util.*;
import lombok.Data;
import org.hibernate.validator.constraints.URL;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

@Data
@ConfigurationProperties(prefix = "app.oauth2")
@Component
@Validated
public class OAuth2ConfigProperties {

    @NotBlank @URL
    private String successRedirectUrl = "http://localhost:5173/dashboard";

    @NotBlank @URL
    private String failureRedirectUrl = "http://localhost:5173/login";

    @NotNull @Valid private RateLimit rateLimit = new RateLimit();

    @NotNull @Valid private Security security = new Security();

    @NotEmpty private Set<@NotBlank String> allowedProviders = Set.of("google");

    private boolean enabled = true;

    // Provider-specific redirect URLs
    private Map<String, String> providerRedirectUrls = new HashMap<>();

    @Data
    @Validated
    public static class RateLimit {
        @Positive @Max(100) private int maxAttemptsPerIp = 10;

        @Positive @Max(20) private int maxAttemptsPerEmail = 5;

        @Positive @Max(60) private int windowMinutes = 15;

        @Positive @Max(120) private int emailWindowMinutes = 30;

        // Progressive backoff settings
        private boolean progressiveBackoffEnabled = true;
        private int baseBackoffMinutes = 1;
        private int maxBackoffMinutes = 60;
    }

    @Data
    @Validated
    public static class Security {
        private boolean csrfEnabled = true;
        private boolean stateValidationEnabled = true;
        private boolean auditLoggingEnabled = true;
        private boolean requireEmailVerified = true;

        @Positive @Max(86400) private int sessionTimeoutSeconds = 3600;

        @Positive @Max(10) private int maxConcurrentSessions = 3;

        // Additional security settings
        private boolean preventAccountEnumeration = true;
        private boolean logSuspiciousActivity = true;
        private Set<String> trustedDomains = new HashSet<>();
    }

    @PostConstruct
    public void validate() {
        // Set default provider-specific redirects if not configured
        if (providerRedirectUrls.isEmpty()) {
            providerRedirectUrls.put("google", successRedirectUrl);
            providerRedirectUrls.put("github", successRedirectUrl);
        }
    }

    public String getRedirectUrlForProvider(String provider) {
        return providerRedirectUrls.getOrDefault(provider, successRedirectUrl);
    }
}
