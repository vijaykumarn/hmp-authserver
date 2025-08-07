package io.vikunalabs.hmp.auth.user.domain;

import lombok.Builder;
import java.time.Instant;

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
    boolean valid
) {}