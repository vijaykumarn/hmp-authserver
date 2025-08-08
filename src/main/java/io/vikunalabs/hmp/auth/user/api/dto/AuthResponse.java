package io.vikunalabs.hmp.auth.user.api.dto;

import java.time.Instant;
import lombok.Builder;

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
        Boolean rememberMe) {}
