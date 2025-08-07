package io.vikunalabs.hmp.auth.oauth2;

import io.vikunalabs.hmp.auth.user.domain.User;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
@Service
public class OAuth2AuditService {

    public void logOAuth2Attempt(String provider, String email, String clientIp, String userAgent) {
        log.info("OAuth2_ATTEMPT: provider={}, email={}, ip={}, userAgent={}, timestamp={}", 
                provider, email != null ? maskEmail(email) : "unknown", clientIp, 
                userAgent != null ? userAgent.substring(0, Math.min(50, userAgent.length())) : "unknown",
                Instant.now());
    }

    public void logOAuth2Success(User user, String provider, String clientIp, String userAgent, boolean isNewUser) {
        log.info("OAuth2_SUCCESS: userId={}, email={}, provider={}, newUser={}, ip={}, userAgent={}, timestamp={}", 
                user.getId(), maskEmail(user.getEmail()), provider, isNewUser, clientIp,
                userAgent != null ? userAgent.substring(0, Math.min(50, userAgent.length())) : "unknown",
                Instant.now());
    }

    public void logOAuth2Failure(String provider, String email, String errorCode, String clientIp, String userAgent) {
        log.warn("OAuth2_FAILURE: provider={}, email={}, error={}, ip={}, userAgent={}, timestamp={}", 
                provider, email != null ? maskEmail(email) : "unknown", errorCode, clientIp,
                userAgent != null ? userAgent.substring(0, Math.min(50, userAgent.length())) : "unknown",
                Instant.now());
    }

    public void logOAuth2SecurityViolation(String provider, String email, String violation, String clientIp) {
        log.error("OAuth2_SECURITY_VIOLATION: provider={}, email={}, violation={}, ip={}, timestamp={}", 
                provider, email != null ? maskEmail(email) : "unknown", violation, clientIp, Instant.now());
    }

    public void logOAuth2RateLimit(String rateLimitType, String identifier, String clientIp) {
        log.warn("OAuth2_RATE_LIMIT: type={}, identifier={}, ip={}, timestamp={}", 
                rateLimitType, maskIdentifier(identifier), clientIp, Instant.now());
    }

    public void logOAuth2UserDataIssue(String provider, String issue, Map<String, Object> attributes) {
        log.warn("OAuth2_USER_DATA_ISSUE: provider={}, issue={}, hasEmail={}, hasSub={}, timestamp={}", 
                provider, issue, 
                attributes.containsKey("email"), 
                attributes.containsKey("sub"),
                Instant.now());
    }

    public String getClientIP(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (StringUtils.hasText(xForwardedFor)) {
            return xForwardedFor.split(",")[0].trim();
        }
        String xRealIp = request.getHeader("X-Real-IP");
        if (StringUtils.hasText(xRealIp)) {
            return xRealIp;
        }
        return request.getRemoteAddr();
    }

    public String getUserAgent(HttpServletRequest request) {
        return request.getHeader("User-Agent");
    }

    private String maskEmail(String email) {
        if (!StringUtils.hasText(email) || !email.contains("@")) {
            return "invalid-email";
        }
        String[] parts = email.split("@");
        String localPart = parts[0];
        String domain = parts[1];
        
        if (localPart.length() <= 2) {
            return "**@" + domain;
        }
        return localPart.substring(0, 2) + "***@" + domain;
    }

    private String maskIdentifier(String identifier) {
        if (!StringUtils.hasText(identifier)) {
            return "unknown";
        }
        if (identifier.length() <= 4) {
            return "****";
        }
        return identifier.substring(0, 2) + "***" + identifier.substring(identifier.length() - 2);
    }
}