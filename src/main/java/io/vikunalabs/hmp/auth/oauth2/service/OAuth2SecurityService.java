package io.vikunalabs.hmp.auth.oauth2.service;

import io.vikunalabs.hmp.auth.oauth2.audit.OAuth2AuditService;
import io.vikunalabs.hmp.auth.shared.config.OAuth2ConfigProperties;
import io.vikunalabs.hmp.auth.shared.exception.OAuth2ProviderException;
import io.vikunalabs.hmp.auth.shared.exception.TooManyRequestsException;
import io.vikunalabs.hmp.auth.user.domain.User;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@Slf4j
@RequiredArgsConstructor
@Service
public class OAuth2SecurityService {

    private final OAuth2RateLimitingService rateLimitingService;
    private final OAuth2AuditService auditService;
    private final OAuth2ConfigProperties config;

    /**
     * Performs security checks for OAuth2/OIDC requests
     */
    public void performSecurityChecks(String registrationId) {
        HttpServletRequest request = getCurrentRequest();
        String clientIp = request != null ? auditService.getClientIP(request) : "unknown";
        String userAgent = request != null ? auditService.getUserAgent(request) : "unknown";

        log.info("OAuth2/OIDC login attempt with provider: {}", registrationId);

        // Rate limiting checks
        try {
            rateLimitingService.checkOAuth2AttemptLimit(clientIp, "unknown");
        } catch (TooManyRequestsException e) {
            auditService.logOAuth2RateLimit("oauth2_attempt", clientIp, clientIp);
            throw new OAuth2AuthenticationException(new OAuth2Error("rate_limit_exceeded", e.getMessage(), null));
        }

        // Log the attempt
        auditService.logOAuth2Attempt(registrationId, "unknown", clientIp, userAgent);
    }

    /**
     * Performs additional security checks once we have user email
     */
    public void performEmailSecurityChecks(String email) {
        try {
            rateLimitingService.checkOAuth2EmailLimit(email);
        } catch (TooManyRequestsException e) {
            HttpServletRequest request = getCurrentRequest();
            String clientIp = request != null ? auditService.getClientIP(request) : "unknown";
            auditService.logOAuth2RateLimit("oauth2_email", email, clientIp);
            throw new OAuth2AuthenticationException(new OAuth2Error("rate_limit_exceeded", e.getMessage(), null));
        }
    }

    /**
     * Logs successful authentication and clears rate limits
     */
    public void logSuccessAndClearLimits(User user, String provider, boolean isNewUser) {
        HttpServletRequest request = getCurrentRequest();
        if (request != null) {
            String clientIp = auditService.getClientIP(request);
            String userAgent = auditService.getUserAgent(request);

            auditService.logOAuth2Success(user, provider, clientIp, userAgent, isNewUser);
            rateLimitingService.clearOAuth2RateLimit(clientIp, user.getEmail());
        }
    }

    /**
     * Logs authentication failure
     */
    public void logFailure(String provider, String email, String errorType) {
        HttpServletRequest request = getCurrentRequest();
        if (request != null) {
            String clientIp = auditService.getClientIP(request);
            String userAgent = auditService.getUserAgent(request);

            auditService.logOAuth2Failure(provider, email, errorType, clientIp, userAgent);
        }
    }

    /**
     * Validates if the provider is allowed
     */
    public void validateProvider(String provider) {
        if (!config.getAllowedProviders().contains(provider)) {
            throw OAuth2ProviderException.unsupportedProvider(provider);
        }
    }

    private HttpServletRequest getCurrentRequest() {
        try {
            ServletRequestAttributes attributes =
                    (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
            return attributes.getRequest();
        } catch (Exception e) {
            return null;
        }
    }
}
