package io.vikunalabs.hmp.auth.oauth2.domain.exception;

import io.vikunalabs.hmp.auth.shared.exception.AuthException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

public class OAuth2ProcessingException extends AuthException {
    private final String provider;
    private final String userId;
    private final String step;
    private final Map<String, Object> context;

    public OAuth2ProcessingException(
            String provider, String userId, String step, String message, Map<String, Object> context) {
        super(String.format("[%s] Error in %s for user %s: %s", provider, step, userId, message));
        this.provider = provider;
        this.userId = userId;
        this.step = step;
        this.context = context != null ? context : new HashMap<>();
    }

    // Static factory methods with context
    public static OAuth2ProcessingException userCreationFailed(String provider, String email, Throwable cause) {
        Map<String, Object> context = Map.of(
                "email", email,
                "timestamp", Instant.now(),
                "errorType", cause.getClass().getSimpleName());
        return new OAuth2ProcessingException(provider, email, "user_creation", "Failed to create user", context);
    }

    // Getters for structured logging
    public String getProvider() {
        return provider;
    }

    public String getUserId() {
        return userId;
    }

    public String getStep() {
        return step;
    }

    public Map<String, Object> getContext() {
        return context;
    }
}
