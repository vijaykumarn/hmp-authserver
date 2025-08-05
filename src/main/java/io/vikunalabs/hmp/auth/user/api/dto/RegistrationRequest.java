package io.vikunalabs.hmp.auth.user.api.dto;

import jakarta.validation.constraints.*;
import java.io.Serializable;

public record RegistrationRequest(
        @NotBlank @Size(min = 3, max = 20) @Pattern(regexp = "^[a-zA-Z0-9.]+$") String username,
        @NotBlank @Email String email,
        @NotBlank @Size(min = 8) String password,
        String organisation,
        @AssertTrue Boolean terms,
        Boolean marketing)
        implements Serializable {}
