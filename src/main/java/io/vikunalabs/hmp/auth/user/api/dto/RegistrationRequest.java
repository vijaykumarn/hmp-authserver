package io.vikunalabs.hmp.auth.user.api.dto;

import jakarta.validation.constraints.*;
import java.io.Serializable;

public record RegistrationRequest(
        @NotBlank(message = "Username is required")
        @Size(min = 3, max = 20, message = "Username must be between 3 and 20 characters")
        @Pattern(regexp = "^[a-zA-Z0-9._-]+$", message = "Username can only contain letters, numbers, dots, underscores and hyphens")
        String username,

        @NotBlank(message = "Email is required")
        @Email(message = "Please provide a valid email address")
        @Size(max = 255, message = "Email cannot exceed 255 characters")
        String email,

        @NotBlank(message = "Password is required")
        @Size(min = 8, max = 100, message = "Password must be between 8 and 100 characters")
        @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&].*$",
                message = "Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character")
        String password,

        @Size(max = 100, message = "Organisation name cannot exceed 100 characters")
        String organisation,

        @NotNull(message = "Terms acceptance is required")
        @AssertTrue(message = "You must accept the terms and conditions")
        Boolean terms,

        Boolean marketing)
        implements Serializable {}
