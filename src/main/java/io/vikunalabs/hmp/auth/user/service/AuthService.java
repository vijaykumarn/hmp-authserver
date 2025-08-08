package io.vikunalabs.hmp.auth.user.service;

import io.vikunalabs.hmp.auth.shared.ApiResponse;
import io.vikunalabs.hmp.auth.user.api.dto.*;
import io.vikunalabs.hmp.auth.user.domain.TokenType;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.UUID;
import org.springframework.security.core.Authentication;

public interface AuthService {

    ApiResponse<RegistrationResponse> register(RegistrationRequest request);

    ApiResponse<String> confirmAccount(UUID tokenValue, TokenType tokenType);

    ApiResponse<String> resendVerificationCode(ResendVerificationRequest request);

    ApiResponse<AuthResponse> handleSuccessfulLogin(
            Authentication authentication,
            boolean rememberMe,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse);

    ApiResponse<String> logout(HttpServletRequest request, HttpServletResponse response);

    ApiResponse<String> forgotPassword(ForgotPasswordRequest request);

    ApiResponse<String> resetPassword(UUID tokenValue, String newPassword);

    ApiResponse<String> confirmPasswordToken(UUID tokenValue);
}
