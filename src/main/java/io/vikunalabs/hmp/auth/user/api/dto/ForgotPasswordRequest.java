package io.vikunalabs.hmp.auth.user.api.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record ForgotPasswordRequest(
    @NotBlank(message = "Email is required")
    @Email(message = "Email should be valid")
    String email
) {}