package io.vikunalabs.hmp.auth.user.service;

import io.vikunalabs.hmp.auth.shared.ApiResponse;
import io.vikunalabs.hmp.auth.user.api.dto.RegistrationRequest;
import io.vikunalabs.hmp.auth.user.api.dto.RegistrationResponse;
import io.vikunalabs.hmp.auth.user.api.dto.ResendVerificationRequest;
import io.vikunalabs.hmp.auth.user.domain.TokenType;

import java.util.UUID;

public interface AuthService {

    ApiResponse<RegistrationResponse> register(RegistrationRequest request);

    ApiResponse<String> confirmAccount(UUID tokenValue, TokenType tokenType);

    ApiResponse<String> resendVerificationCode(ResendVerificationRequest request);

}
