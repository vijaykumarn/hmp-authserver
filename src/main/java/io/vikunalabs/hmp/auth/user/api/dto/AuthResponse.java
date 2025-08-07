package io.vikunalabs.hmp.auth.user.api.dto;

import lombok.Builder;
import java.time.Instant;

@Builder
public record AuthResponse(
    Long userId,
    String email,
    String username,
    String firstName,
    String lastName,
    String fullName,
    String role,
    Instant lastLogin,
    Boolean rememberMe
) {}