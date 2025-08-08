package io.vikunalabs.hmp.auth.oauth2.service;

import io.vikunalabs.hmp.auth.oauth2.domain.model.OAuth2UserInfo;
import io.vikunalabs.hmp.auth.shared.exception.OAuth2EmailConflictException;
import io.vikunalabs.hmp.auth.shared.exception.UserNotFoundException;
import io.vikunalabs.hmp.auth.user.domain.User;
import io.vikunalabs.hmp.auth.user.domain.UserRole;
import io.vikunalabs.hmp.auth.user.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Slf4j
@RequiredArgsConstructor
@Service
public class OAuth2UserProcessor {

    private final UserService userService;

    /**
     * Processes OAuth2/OIDC user - creates or finds existing user
     */
    public User processUser(OAuth2UserInfo userInfo, String provider) {
        log.info("=== Processing OAuth2/OIDC user START ===");
        log.info("Provider: {}, Email: {}, Subject: {}", provider, userInfo.getEmail(), userInfo.getId());

        // Validate user info
        userInfo.validateRequiredFields();

        // Try to find existing user by provider and providerId
        try {
            log.info("Looking for existing user with provider: {} and providerId: {}", provider, userInfo.getId());
            User existingUser = userService.findByProviderAndProviderId(provider, userInfo.getId());
            log.info("Found existing OAuth2/OIDC user: {}", existingUser.getEmail());

            // Update user info if needed (email, names might have changed)
            return updateUserIfNeeded(existingUser, userInfo);

        } catch (UserNotFoundException e) {
            log.info("No existing OAuth2/OIDC user found, checking for email conflicts");
            return handleNewUser(userInfo, provider);
        }
    }

    private User updateUserIfNeeded(User existingUser, OAuth2UserInfo userInfo) {
        boolean updated = false;

        // Check if email has changed on the provider side
        if (!existingUser.getEmail().equals(userInfo.getEmail())) {
            log.warn("Email changed for OAuth2 user - Old: {}, New: {}", existingUser.getEmail(), userInfo.getEmail());
            existingUser.setEmail(userInfo.getEmail());
            updated = true;
        }

        // Update first name if not set or different
        if (shouldUpdateField(existingUser.getFirstName(), userInfo.getFirstName())) {
            existingUser.setFirstName(userInfo.getFirstName());
            updated = true;
        }

        // Update last name if not set or different
        if (shouldUpdateField(existingUser.getLastName(), userInfo.getLastName())) {
            existingUser.setLastName(userInfo.getLastName());
            updated = true;
        }

        if (updated) {
            log.info("Updating OAuth2 user info for user: {}", existingUser.getEmail());
            return userService.save(existingUser);
        }

        return existingUser;
    }

    private boolean shouldUpdateField(String currentValue, String newValue) {
        return (!StringUtils.hasText(currentValue) && StringUtils.hasText(newValue))
                || (StringUtils.hasText(currentValue)
                        && StringUtils.hasText(newValue)
                        && !currentValue.equals(newValue));
    }

    private User handleNewUser(OAuth2UserInfo userInfo, String provider) {
        // Check if email is already taken by local account
        try {
            log.info("Checking if email {} already exists", userInfo.getEmail());
            User existingEmailUser = userService.findByEmail(userInfo.getEmail());
            log.warn("Email {} already exists with provider: {}", userInfo.getEmail(), existingEmailUser.getProvider());

            String existingProvider = "local".equals(existingEmailUser.getProvider())
                    ? "email/password"
                    : existingEmailUser.getProvider();
            throw OAuth2EmailConflictException.withEmail(userInfo.getEmail(), existingProvider);

        } catch (UserNotFoundException e) {
            log.info("Email not found, proceeding with user creation");
            return createNewUser(userInfo, provider);
        }
    }

    private User createNewUser(OAuth2UserInfo userInfo, String provider) {
        log.info("=== CREATING NEW OAUTH2/OIDC USER ===");

        String username = userService.generateUniqueUsername(userInfo.getEmail());
        log.info("Generated username: {}", username);

        User newUser = User.builder()
                .username(username)
                .email(userInfo.getEmail())
                .password("") // Empty password for OAuth2 users
                .firstName(userInfo.getFirstName())
                .lastName(userInfo.getLastName())
                .provider(provider)
                .providerId(userInfo.getId())
                .role(UserRole.USER)
                .accountEnabled(true)
                .emailVerified(true) // OAuth2 emails are pre-verified
                .credentialsExpired(false)
                .accountExpired(false)
                .accountLocked(false)
                .failedLoginAttempts(0)
                .consent(true) // OAuth2 users implicitly accept terms
                .notification(false)
                .build();

        try {
            User savedUser = userService.save(newUser);
            log.info(
                    "Successfully saved OAuth2/OIDC user with ID: {} and email: {}",
                    savedUser.getId(),
                    savedUser.getEmail());
            return savedUser;
        } catch (Exception e) {
            log.error("FAILED to save OAuth2/OIDC user!", e);
            throw new RuntimeException("Failed to create OAuth2/OIDC user", e);
        }
    }
}
