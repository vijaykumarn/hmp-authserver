package io.vikunalabs.hmp.auth.user.api.dto;

import lombok.Builder;

@Builder
public record RegistrationResponse(
        Long id,
        String email,
        String username,
        String firstName,
        String lastName,
        String organisation
) {}