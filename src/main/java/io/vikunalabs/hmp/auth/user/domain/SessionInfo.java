package io.vikunalabs.hmp.auth.user.domain;

import java.time.Instant;
import lombok.Builder;

@Builder
public record SessionInfo(
        String sessionId,
        Long userId,
        String userEmail,
        String ipAddress,
        String userAgent,
        Instant createdAt,
        Instant lastAccessedAt,
        boolean rememberMe,
        boolean valid) {}
