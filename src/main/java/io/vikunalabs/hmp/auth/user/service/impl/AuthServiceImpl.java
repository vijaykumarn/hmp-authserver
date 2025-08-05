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
public class AuthServiceImpl implements AuthService {

    private final UserAccountService accountService;
    private final UserProfileService profileService;
    private final TokenService tokenService;
    private final ApplicationEventPublisher eventPublisher;

    @Override
    @Transactional
    public ApiResponse<RegistrationResponse> register(RegistrationRequest request) {
        log.debug("Attempting to register user with username: {}", request.username());

        accountService.validateUniqueUsernameAndEmail(request.username(), request.email());
        var userProfile = profileService.createUserProfile(request);

        publishRegistrationEvent(userProfile.getId());
        log.info("Successfully registered user with ID: {}", userProfile.getId());
        return new ApiResponse<RegistrationResponse>(true, mapToRegistrationResponse(userProfile), null, "Registration successful! Please check your email to verify your account.");

    }

    @Override
    @Transactional
    public ApiResponse<String> confirmAccount(UUID tokenValue, TokenType tokenType) {
        log.info("Attempting to activate account with token: {}", tokenValue);

        var token = tokenService.confirmToken(tokenValue, tokenType);
        var userAccount = accountService.enableUserAccount(token.getUserAccount().getId());

        log.info("Successfully activated account for user ID: {}", userAccount.getId());
        publishAccountActivationEvent(userAccount);

        return new ApiResponse<>(true, null, "Account verified successfully! You can now log in.");
    }

    @Override
    public ApiResponse<String> resendVerificationCode(ResendVerificationRequest request) {

        // Rate limiting - allow only one request per 5 minutes
        if (tokenService.hasRecentTokenRequest(request.email(), TokenType.EMAIL_VERIFICATION, 5)) {
            throw new TooManyRequestsException("Please wait before requesting another verification email");
        }

        UserAccount userAccount = accountService.findByEmail(request.email());
        if (userAccount.isEmailVerified()) {
            throw AccountAlreadyActivatedException.withEmail(request.email());
        }

        Token token = tokenService.createToken(userAccount.getId(), TokenType.EMAIL_VERIFICATION);

        // send email
        String confirmationLink = String.format("%s?token=%s", "http://localhost:8080/api/auth/confirm-account", token.getValue());
        log.info("Generated confirmation link for user {}: {}", userAccount.getId(), confirmationLink);
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
