package io.vikunalabs.hmp.auth.user.service.impl;

import io.vikunalabs.hmp.auth.shared.ApiResponse;
import io.vikunalabs.hmp.auth.shared.exception.AccountAlreadyActivatedException;
import io.vikunalabs.hmp.auth.shared.exception.TooManyRequestsException;
import io.vikunalabs.hmp.auth.shared.exception.UserNotFoundException;
import io.vikunalabs.hmp.auth.user.api.dto.*;
import io.vikunalabs.hmp.auth.user.domain.Token;
import io.vikunalabs.hmp.auth.user.domain.TokenType;
import io.vikunalabs.hmp.auth.user.domain.User;
import io.vikunalabs.hmp.auth.user.domain.UserRole;
import io.vikunalabs.hmp.auth.user.events.UserActivationEvent;
import io.vikunalabs.hmp.auth.user.events.UserRegistrationEvent;
import io.vikunalabs.hmp.auth.user.service.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Slf4j
@RequiredArgsConstructor
@Service
@Transactional(readOnly = true)
public class AuthServiceImpl implements AuthService {

    private final UserService userService;
    private final TokenService tokenService;
    private final SessionService sessionService;
    private final PasswordEncoder passwordEncoder;
    private final ApplicationEventPublisher eventPublisher;

    @Override
    @Transactional
    public ApiResponse<RegistrationResponse> register(RegistrationRequest request) {
        log.debug("Attempting to register user with username: {} and email: {}",
                request.username(), request.email());

        // Validate unique username and email
        userService.validateUniqueUsernameAndEmail(request.username(), request.email());

        // Create user entity
        User user = createUserFromRequest(request);
        User savedUser = userService.save(user);

        // Publish registration event for email verification
        publishRegistrationEvent(savedUser.getId());

        log.info("Successfully registered user with ID: {} and email: {}",
                savedUser.getId(), savedUser.getEmail());

        return new ApiResponse<>(
                true,
                mapToRegistrationResponse(savedUser),
                null,
                "Registration successful! Please check your email to verify your account."
        );
    }

    @Override
    @Transactional
    public ApiResponse<String> confirmAccount(UUID tokenValue, TokenType tokenType) {
        log.info("Attempting to activate account with token: {}", tokenValue);

        Token token = tokenService.confirmToken(tokenValue, tokenType);
        User user = userService.enableUser(token.getUser().getId());

        log.info("Successfully activated account for user ID: {} with email: {}",
                user.getId(), user.getEmail());

        publishAccountActivationEvent(user);

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

        User user = userService.findByEmail(request.email());

        if (user.isEmailVerified()) {
            log.warn("Verification requested for already verified account: {}", request.email());
            throw AccountAlreadyActivatedException.withEmail(request.email());
        }

        Token token = tokenService.createToken(user.getId(), TokenType.EMAIL_VERIFICATION);
        log.info("Generated verification token for user {}: {}", user.getId(), token.getValue());

        return new ApiResponse<>(true, "Verification email sent! Please check your email.");
    }

    @Override
    @Transactional
    public ApiResponse<AuthResponse> handleSuccessfulLogin(
            Authentication authentication,
            boolean rememberMe,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {

        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        User user = userService.findById(userDetails.getUserId());

        // Reset failed login attempts on successful login
        if (user.getFailedLoginAttempts() > 0) {
            userService.resetFailedLoginAttempts(user);
        }

        // Create session
        sessionService.createSession(user, rememberMe, httpRequest, httpResponse);

        log.info("Successful login for user: {} (ID: {})", user.getEmail(), user.getId());

        return new ApiResponse<>(
                true,
                mapToAuthResponse(user),
                null,
                "Login successful"
        );
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
            User user = userService.findByEmail(request.email());

            if (!user.isAccountEnabled() || !user.isEmailVerified()) {
                log.warn("Password reset requested for inactive account: {}", request.email());
                // Return success to prevent email enumeration
                return new ApiResponse<>(true, "If the email exists, a password reset link has been sent.");
            }

            Token token = tokenService.createToken(user.getId(), TokenType.PASSWORD_RESET);
            log.info("Generated password reset token for user {}: {}", user.getId(), token.getValue());

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
        User user = token.getUser();

        String encodedPassword = passwordEncoder.encode(newPassword);
        user.setPassword(encodedPassword);
        user.setCredentialsExpired(false);

        userService.save(user);

        log.info("Password reset successful for user ID: {}", user.getId());

        return new ApiResponse<>(true, "Password reset successful. You can now log in with your new password.");
    }

    @Override
    public ApiResponse<String> confirmPasswordToken(UUID tokenValue) {
        log.info("Password token validation for token: {}", tokenValue);

        tokenService.findValidToken(tokenValue, TokenType.PASSWORD_RESET);

        return new ApiResponse<>(true, "Password reset token is valid");
    }

    // Private helper methods

    private User createUserFromRequest(RegistrationRequest request) {
        return User.builder()
                .username(request.username())
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .role(UserRole.USER)
                .accountEnabled(true)
                .emailVerified(false)
                .credentialsExpired(false)
                .accountExpired(false)
                .accountLocked(false)
                .rememberMe(false)
                .failedLoginAttempts(0)
                .provider("local")
                // Profile fields
                .organisation(request.organisation())
                .consent(request.terms())
                .notification(request.marketing())
                .build();
    }

    private void publishAccountActivationEvent(User user) {
        eventPublisher.publishEvent(new UserActivationEvent(user.getId()));
    }

    private void publishRegistrationEvent(Long userId) {
        eventPublisher.publishEvent(new UserRegistrationEvent(userId));
    }

    private RegistrationResponse mapToRegistrationResponse(User user) {
        return RegistrationResponse.builder()
                .id(user.getId())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .email(user.getEmail())
                .username(user.getUsername())
                .organisation(user.getOrganisation())
                .build();
    }

    private AuthResponse mapToAuthResponse(User user) {
        return AuthResponse.builder()
                .userId(user.getId())
                .email(user.getEmail())
                .username(user.getUsername())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .fullName(user.getFullName())
                .role(user.getRole().name())
                .lastLogin(user.getLastLogin())
                .rememberMe(user.isRememberMe())
                .build();
    }

    // Add this method to handle authentication failures
    @EventListener
    public void handleAuthenticationFailure(AbstractAuthenticationFailureEvent event) {
        String username = event.getAuthentication().getName();

        try {
            User user = userService.findByUsernameOrEmail(username);
            userService.recordFailedLoginAttempt(user);
            log.warn("Recorded failed login attempt for user: {} (Total attempts: {})",
                    user.getEmail(), user.getFailedLoginAttempts());
        } catch (UserNotFoundException e) {
            log.debug("Failed login attempt for non-existent user: {}", username);
            // Don't reveal that user doesn't exist
        }
    }
}