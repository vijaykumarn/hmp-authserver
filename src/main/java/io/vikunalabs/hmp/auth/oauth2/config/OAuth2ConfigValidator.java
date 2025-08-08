package io.vikunalabs.hmp.auth.oauth2.config;

import io.vikunalabs.hmp.auth.shared.config.OAuth2ConfigProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Slf4j
@RequiredArgsConstructor
@Component
public class OAuth2ConfigValidator {

    private final OAuth2ConfigProperties oauth2Config;
    private final Environment environment;

    @EventListener(ApplicationReadyEvent.class)
    public void validateOAuth2Configuration() {
        if (!oauth2Config.isEnabled()) {
            log.info("OAuth2 is disabled");
            return;
        }

        log.info("Validating OAuth2 configuration...");

        // Validate Google OAuth2 credentials
        validateGoogleCredentials();

        // Validate redirect URLs
        validateRedirectUrls();

        // Validate rate limiting configuration
        validateRateLimitConfig();

        // Validate security configuration
        validateSecurityConfig();

        // Log configuration summary
        logConfigurationSummary();

        log.info("OAuth2 configuration validation completed successfully");
    }

    private void validateGoogleCredentials() {
        String clientId = environment.getProperty("spring.security.oauth2.client.registration.google.client-id");
        String clientSecret =
                environment.getProperty("spring.security.oauth2.client.registration.google.client-secret");

        if (!StringUtils.hasText(clientId) || "your-google-client-id".equals(clientId)) {
            log.error("Google OAuth2 client-id is not configured! Set GOOGLE_CLIENT_ID environment variable.");
            throw new IllegalStateException("Google OAuth2 client-id is required");
        }

        if (!StringUtils.hasText(clientSecret) || "your-google-client-secret".equals(clientSecret)) {
            log.error("Google OAuth2 client-secret is not configured! Set GOOGLE_CLIENT_SECRET environment variable.");
            throw new IllegalStateException("Google OAuth2 client-secret is required");
        }

        log.info("✓ Google OAuth2 credentials configured");
    }

    private void validateRedirectUrls() {
        if (!StringUtils.hasText(oauth2Config.getSuccessRedirectUrl())) {
            throw new IllegalStateException("OAuth2 success redirect URL is required");
        }

        if (!StringUtils.hasText(oauth2Config.getFailureRedirectUrl())) {
            throw new IllegalStateException("OAuth2 failure redirect URL is required");
        }

        String redirectUri = environment.getProperty("spring.security.oauth2.client.registration.google.redirect-uri");
        if (!StringUtils.hasText(redirectUri)) {
            throw new IllegalStateException("Google OAuth2 redirect URI is required");
        }

        log.info("✓ OAuth2 redirect URLs configured");
        log.info("  Success: {}", oauth2Config.getSuccessRedirectUrl());
        log.info("  Failure: {}", oauth2Config.getFailureRedirectUrl());
        log.info("  Google callback: {}", redirectUri);
    }

    private void validateRateLimitConfig() {
        OAuth2ConfigProperties.RateLimit rateLimit = oauth2Config.getRateLimit();

        if (rateLimit.getMaxAttemptsPerIp() <= 0) {
            throw new IllegalStateException("OAuth2 max attempts per IP must be positive");
        }

        if (rateLimit.getMaxAttemptsPerEmail() <= 0) {
            throw new IllegalStateException("OAuth2 max attempts per email must be positive");
        }

        if (rateLimit.getWindowMinutes() <= 0) {
            throw new IllegalStateException("OAuth2 rate limit window must be positive");
        }

        log.info(
                "✓ OAuth2 rate limiting configured: {}/{} attempts per IP/email in {}/{} minutes",
                rateLimit.getMaxAttemptsPerIp(),
                rateLimit.getMaxAttemptsPerEmail(),
                rateLimit.getWindowMinutes(),
                rateLimit.getEmailWindowMinutes());
    }

    private void validateSecurityConfig() {
        OAuth2ConfigProperties.Security security = oauth2Config.getSecurity();

        if (security.getSessionTimeoutSeconds() <= 0) {
            throw new IllegalStateException("OAuth2 session timeout must be positive");
        }

        if (security.getMaxConcurrentSessions() <= 0) {
            throw new IllegalStateException("OAuth2 max concurrent sessions must be positive");
        }

        log.info(
                "✓ OAuth2 security configured: CSRF={}, StateValidation={}, AuditLogging={}",
                security.isCsrfEnabled(),
                security.isStateValidationEnabled(),
                security.isAuditLoggingEnabled());
    }

    private void logConfigurationSummary() {
        String activeProfile = environment.getProperty("spring.profiles.active", "default");

        log.info("=== OAuth2 Configuration Summary ===");
        log.info("Environment: {}", activeProfile);
        log.info("Enabled: {}", oauth2Config.isEnabled());
        log.info("Allowed Providers: {}", oauth2Config.getAllowedProviders());
        log.info("CSRF Protection: {}", oauth2Config.getSecurity().isCsrfEnabled());
        log.info("Audit Logging: {}", oauth2Config.getSecurity().isAuditLoggingEnabled());

        if ("production".equals(activeProfile)) {
            validateProductionSettings();
        }

        log.info("=====================================");
    }

    private void validateProductionSettings() {
        log.info("Validating production-specific settings...");

        // Check if HTTPS is configured
        String serverPort = environment.getProperty("server.port", "8080");
        String redirectUri = environment.getProperty("spring.security.oauth2.client.registration.google.redirect-uri");

        if (redirectUri != null && !redirectUri.startsWith("https://")) {
            log.warn("⚠️  Production OAuth2 redirect URI should use HTTPS: {}", redirectUri);
        }

        // Check secure cookie settings
        String cookieSecure = environment.getProperty("server.servlet.session.cookie.secure");
        if (!"true".equals(cookieSecure)) {
            log.warn("⚠️  Production should set server.servlet.session.cookie.secure=true");
        }

        String sameSite = environment.getProperty("server.servlet.session.cookie.same-site");
        if (!"strict".equalsIgnoreCase(sameSite)) {
            log.warn("⚠️  Production should set server.servlet.session.cookie.same-site=strict");
        }

        log.info("✓ Production settings validation completed");
    }
}
