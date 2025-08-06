package io.vikunalabs.hmp.auth.user.service.impl;

import io.vikunalabs.hmp.auth.shared.ApiResponse;
import io.vikunalabs.hmp.auth.shared.exception.*;
import io.vikunalabs.hmp.auth.user.api.dto.*;
import io.vikunalabs.hmp.auth.user.domain.Token;
import io.vikunalabs.hmp.auth.user.domain.TokenType;
import io.vikunalabs.hmp.auth.user.domain.UserAccount;
import io.vikunalabs.hmp.auth.user.domain.UserProfile;
import io.vikunalabs.hmp.auth.user.events.UserAccountActivationEvent;
import io.vikunalabs.hmp.auth.user.events.UserRegistrationEvent;
import io.vikunalabs.hmp.auth.user.service.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Slf4j
@RequiredArgsConstructor
@Service
@Transactional(readOnly = true)
public class AuthServiceImpl implements AuthService {

    private final UserAccountService accountService;
    private final UserProfileService profileService;
    private final TokenService tokenService;
    private final SessionService sessionService;
    private final PasswordEncoder passwordEncoder;
    private final ApplicationEventPublisher eventPublisher;

    @Override
    @Transactional
    public ApiResponse<RegistrationResponse> register(RegistrationRequest request) {
        log.debug("Attempting to register user with username: {} and email: {}",
                request.username(), request.email());

        accountService.validateUniqueUsernameAndEmail(request.username(), request.email());
        UserProfile userProfile = profileService.createUserProfile(request);

        publishRegistrationEvent(userProfile.getId());

        log.info("Successfully registered user with ID: {} and email: {}",
                userProfile.getId(), request.email());

        return new ApiResponse<>(
                true,
                mapToRegistrationResponse(userProfile),
                null,
                "Registration successful! Please check your email to verify your account."
        );
    }

    @Override
    @Transactional
    public ApiResponse<String> confirmAccount(UUID tokenValue, TokenType tokenType) {
        log.info("Attempting to activate account with token: {}", tokenValue);

        Token token = tokenService.confirmToken(tokenValue, tokenType);
        UserAccount userAccount = accountService.enableUserAccount(token.getUserAccount().getId());

        log.info("Successfully activated account for user ID: {} with email: {}",
                userAccount.getId(), userAccount.getEmail());

        publishAccountActivationEvent(userAccount);

        return new ApiResponse<>(true, "Account verified successfully! You can now log in.");
    }

    @Override
    @Transactional
    public ApiResponse<String> resendVerificationCode(ResendVerificationRequest request) {
        log.info("Resend verification requested for email: {}", request.email());

        if (tokenService.hasRecentTokenRequest(request.email(), TokenType.EMAIL_VERIFICATION, 5)) {
            log.warn("Rate limit exceeded for email verification request: {}", request.email());
            throw new TooManyRequestsException("Please wait before requesting another verification email");
        }

        UserAccount userAccount = accountService.findByEmail(request.email());

        if (userAccount.isEmailVerified()) {
            log.warn("Verification requested for already verified account: {}", request.email());
            throw AccountAlreadyActivatedException.withEmail(request.email());
        }

        Token token = tokenService.createToken(userAccount.getId(), TokenType.EMAIL_VERIFICATION);
        log.info("Generated verification token for user {}: {}", userAccount.getId(), token.getValue());

        return new ApiResponse<>(true, "Verification email sent! Please check your email.");
    }

    @Override
    @Transactional
    public ApiResponse<String> logout(HttpServletRequest request, HttpServletResponse response) {
        sessionService.invalidateSession(request, response);
        log.info("User logged out successfully");
        return new ApiResponse<>(true, "Logged out successfully");
    }

    @Override
    @Transactional
    public ApiResponse<String> forgotPassword(ForgotPasswordRequest request) {
        log.info("Forgot password request for email: {}", request.email());

        if (tokenService.hasRecentTokenRequest(request.email(), TokenType.PASSWORD_RESET, 5)) {
            log.warn("Rate limit exceeded for password reset request: {}", request.email());
            throw new TooManyRequestsException("Please wait before requesting another password reset email");
        }

        try {
            UserAccount userAccount = accountService.findByEmail(request.email());

            if (!userAccount.isAccountEnabled() || !userAccount.isEmailVerified()) {
                log.warn("Password reset requested for inactive account: {}", request.email());
                // Return success to prevent email enumeration
                return new ApiResponse<>(true, "If the email exists, a password reset link has been sent.");
            }

            Token token = tokenService.createToken(userAccount.getId(), TokenType.PASSWORD_RESET);
            log.info("Generated password reset token for user {}: {}", userAccount.getId(), token.getValue());

        } catch (UserNotFoundException e) {
            log.warn("Password reset requested for non-existent email: {}", request.email());
            // Return success to prevent email enumeration
        }

        return new ApiResponse<>(true, "If the email exists, a password reset link has been sent.");
    }

    @Override
    @Transactional
    public ApiResponse<String> resetPassword(UUID tokenValue, String newPassword) {
        log.info("Password reset attempt with token: {}", tokenValue);

        Token token = tokenService.confirmToken(tokenValue, TokenType.PASSWORD_RESET);
        UserAccount userAccount = token.getUserAccount();

        String encodedPassword = passwordEncoder.encode(newPassword);
        userAccount.setPassword(encodedPassword);
        userAccount.setCredentialsExpired(false);

        accountService.save(userAccount);

        log.info("Password reset successful for user ID: {}", userAccount.getId());

        return new ApiResponse<>(true, "Password reset successful. You can now log in with your new password.");
    }

    @Override
    public ApiResponse<String> confirmPasswordToken(UUID tokenValue) {
        log.info("Password token validation for token: {}", tokenValue);

        tokenService.findValidToken(tokenValue, TokenType.PASSWORD_RESET);

        return new ApiResponse<>(true, "Password reset token is valid");
    }

    @Override
    @Transactional
    public ApiResponse<AuthResponse> handleSuccessfulLogin(
            Authentication authentication,
            boolean rememberMe,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {

        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        UserAccount userAccount = accountService.findById(userDetails.getUserId());

        sessionService.createSession(userAccount, rememberMe, httpRequest, httpResponse);

        log.info("Successful login for user: {}", userDetails.getUsername());

        return new ApiResponse<>(
                true,
                mapToAuthResponse(userAccount),
                null,
                "Login successful"
        );
    }

    private void publishAccountActivationEvent(UserAccount userAccount) {
        eventPublisher.publishEvent(new UserAccountActivationEvent(userAccount.getId()));
    }

    private void publishRegistrationEvent(Long userProfileId) {
        eventPublisher.publishEvent(new UserRegistrationEvent(userProfileId));
    }

    private RegistrationResponse mapToRegistrationResponse(UserProfile profile) {
        return RegistrationResponse.builder()
                .id(profile.getId())
                .firstName(profile.getFirstName())
                .lastName(profile.getLastName())
                .email(profile.getUserAccount().getEmail())
                .username(profile.getUserAccount().getUsername())
                .organisation(profile.getOrganisation())
                .build();
    }

    private AuthResponse mapToAuthResponse(UserAccount userAccount) {
        UserProfile profile = userAccount.getUserProfile();
        return AuthResponse.builder()
                .userId(userAccount.getId())
                .email(userAccount.getEmail())
                .username(userAccount.getUsername())
                .firstName(profile != null ? profile.getFirstName() : null)
                .lastName(profile != null ? profile.getLastName() : null)
                .role(userAccount.getRole().name())
                .lastLogin(userAccount.getLastLogin())
                .rememberMe(userAccount.isRememberMe())
                .build();
    }
}
