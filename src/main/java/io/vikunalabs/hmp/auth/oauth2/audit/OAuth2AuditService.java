package io.vikunalabs.hmp.auth.oauth2.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.vikunalabs.hmp.auth.user.domain.User;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@Slf4j
@RequiredArgsConstructor
@Service
public class OAuth2AuditService {

    private final ObjectMapper objectMapper;

    public void logOAuth2Event(String eventType, Map<String, Object> eventData) {
        try {
            Map<String, Object> auditEntry = new HashMap<>();
            auditEntry.put("timestamp", Instant.now());
            auditEntry.put("eventType", eventType);
            auditEntry.put("service", "oauth2");
            auditEntry.putAll(eventData);

            String jsonLog = objectMapper.writeValueAsString(auditEntry);
            log.info("OAUTH2_AUDIT: {}", jsonLog);

        } catch (Exception e) {
            log.error("Failed to create audit log", e);
            // Fallback to simple logging
            log.info("OAUTH2_AUDIT: eventType={}, data={}", eventType, eventData);
        }
    }

    public void logOAuth2Success(User user, String provider, String clientIp, String userAgent, boolean isNewUser) {
        Map<String, Object> eventData = Map.of(
                "userId", user.getId(),
                "email", maskEmail(user.getEmail()),
                "provider", provider,
                "newUser", isNewUser,
                "clientIp", clientIp,
                "userAgent", truncateUserAgent(userAgent),
                "sessionId", getCurrentSessionId());

        logOAuth2Event("SUCCESS", eventData);
    }

    public void logOAuth2Failure(String provider, String email, String errorCode, String clientIp, String userAgent) {
        Map<String, Object> eventData = Map.of(
                "provider",
                provider,
                "email",
                email != null ? maskEmail(email) : "unknown",
                "errorCode",
                errorCode,
                "clientIp",
                clientIp,
                "userAgent",
                truncateUserAgent(userAgent),
                "sessionId",
                getCurrentSessionId());

        logOAuth2Event("FAILURE", eventData);
    }

    // ADD THESE MISSING METHODS THAT OAuth2SecurityService NEEDS:

    /**
     * Logs OAuth2 login attempts
     */
    public void logOAuth2Attempt(String provider, String email, String clientIp, String userAgent) {
        Map<String, Object> eventData = Map.of(
                "provider",
                provider,
                "email",
                email != null ? maskEmail(email) : "unknown",
                "clientIp",
                clientIp,
                "userAgent",
                truncateUserAgent(userAgent),
                "sessionId",
                getCurrentSessionId());

        logOAuth2Event("ATTEMPT", eventData);
    }

    /**
     * Logs OAuth2 rate limiting events
     */
    public void logOAuth2RateLimit(String rateLimitType, String identifier, String clientIp) {
        Map<String, Object> eventData = Map.of(
                "rateLimitType",
                rateLimitType,
                "identifier",
                maskIdentifier(identifier),
                "clientIp",
                clientIp,
                "sessionId",
                getCurrentSessionId());

        logOAuth2Event("RATE_LIMIT", eventData);
    }

    /**
     * Gets client IP from HTTP request
     */
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

    /**
     * Gets User-Agent from HTTP request
     */
    public String getUserAgent(HttpServletRequest request) {
        return request.getHeader("User-Agent");
    }

    /**
     * Logs OAuth2 security violations
     */
    public void logOAuth2SecurityViolation(String provider, String email, String violation, String clientIp) {
        Map<String, Object> eventData = Map.of(
                "provider", provider,
                "email", email != null ? maskEmail(email) : "unknown",
                "violation", violation,
                "clientIp", clientIp,
                "sessionId", getCurrentSessionId());

        logOAuth2Event("SECURITY_VIOLATION", eventData);
    }

    /**
     * Logs OAuth2 user data issues
     */
    public void logOAuth2UserDataIssue(String provider, String issue, Map<String, Object> attributes) {
        Map<String, Object> eventData = Map.of(
                "provider", provider,
                "issue", issue,
                "hasEmail", attributes.containsKey("email"),
                "hasSub", attributes.containsKey("sub"),
                "sessionId", getCurrentSessionId());

        logOAuth2Event("USER_DATA_ISSUE", eventData);
    }

    // Helper methods for data sanitization
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

    private String truncateUserAgent(String userAgent) {
        if (userAgent == null) return "unknown";
        return userAgent.length() > 100 ? userAgent.substring(0, 100) + "..." : userAgent;
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

    private String getCurrentSessionId() {
        try {
            ServletRequestAttributes attributes =
                    (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
            HttpServletRequest request = attributes.getRequest();
            HttpSession session = request.getSession(false);
            return session != null ? session.getId() : "no-session";
        } catch (Exception e) {
            return "unknown";
        }
    }
}
