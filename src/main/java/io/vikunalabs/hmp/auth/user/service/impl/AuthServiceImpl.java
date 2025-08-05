package io.vikunalabs.hmp.auth.user.service.impl;

import io.vikunalabs.hmp.auth.shared.ApiResponse;
import io.vikunalabs.hmp.auth.shared.exception.AccountAlreadyActivatedException;
import io.vikunalabs.hmp.auth.shared.exception.TooManyRequestsException;
import io.vikunalabs.hmp.auth.user.api.dto.RegistrationRequest;
import io.vikunalabs.hmp.auth.user.api.dto.RegistrationResponse;
import io.vikunalabs.hmp.auth.user.api.dto.ResendVerificationRequest;
import io.vikunalabs.hmp.auth.user.domain.Token;
import io.vikunalabs.hmp.auth.user.domain.TokenType;
import io.vikunalabs.hmp.auth.user.domain.UserAccount;
import io.vikunalabs.hmp.auth.user.domain.UserProfile;
import io.vikunalabs.hmp.auth.user.events.UserAccountActivationEvent;
import io.vikunalabs.hmp.auth.user.events.UserRegistrationEvent;
import io.vikunalabs.hmp.auth.user.service.AuthService;
import io.vikunalabs.hmp.auth.user.service.TokenService;
import io.vikunalabs.hmp.auth.user.service.UserAccountService;
import io.vikunalabs.hmp.auth.user.service.UserProfileService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Slf4j
@RequiredArgsConstructor
@Service
@Transactional(readOnly = true) // Default to read-only for better performance
public class AuthServiceImpl implements AuthService {

    private final UserAccountService accountService;
    private final UserProfileService profileService;
    private final TokenService tokenService;
    private final ApplicationEventPublisher eventPublisher;

    @Override
    @Transactional // Write transaction only where needed
    public ApiResponse<RegistrationResponse> register(RegistrationRequest request) {
        log.debug("Attempting to register user with username: {} and email: {}",
                request.username(), request.email());

        // Validate uniqueness before creating entities
        accountService.validateUniqueUsernameAndEmail(request.username(), request.email());

        // Create user profile with associated account
        UserProfile userProfile = profileService.createUserProfile(request);

        // Publish event for async email processing
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

        // Confirm token and enable account in one transaction
        Token token = tokenService.confirmToken(tokenValue, tokenType);
        UserAccount userAccount = accountService.enableUserAccount(token.getUserAccount().getId());

        log.info("Successfully activated account for user ID: {} with email: {}",
                userAccount.getId(), userAccount.getEmail());

        // Publish activation event
        publishAccountActivationEvent(userAccount);

        return new ApiResponse<>(true, null, "Account verified successfully! You can now log in.");
    }

    @Override
    @Transactional // Need write access for token creation
    public ApiResponse<String> resendVerificationCode(ResendVerificationRequest request) {
        log.info("Resend verification requested for email: {}", request.email());

        // Rate limiting check
        if (tokenService.hasRecentTokenRequest(request.email(), TokenType.EMAIL_VERIFICATION, 5)) {
            log.warn("Rate limit exceeded for email verification request: {}", request.email());
            throw new TooManyRequestsException("Please wait before requesting another verification email");
        }

        // Find user account
        UserAccount userAccount = accountService.findByEmail(request.email());

        // Check if already verified
        if (userAccount.isEmailVerified()) {
            log.warn("Verification requested for already verified account: {}", request.email());
            throw AccountAlreadyActivatedException.withEmail(request.email());
        }

        // Create new verification token
        Token token = tokenService.createToken(userAccount.getId(), TokenType.EMAIL_VERIFICATION);

        // Log for testing (in production, this would trigger email service)
        log.info("Generated verification token for user {}: {}", userAccount.getId(), token.getValue());

        return new ApiResponse<>(true, "Verification email sent! Please check your email.");
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
}
