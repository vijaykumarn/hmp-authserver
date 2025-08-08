package io.vikunalabs.hmp.auth.user.service.impl;

import io.vikunalabs.hmp.auth.shared.exception.EmailAlreadyTakenException;
import io.vikunalabs.hmp.auth.shared.exception.UserNotFoundException;
import io.vikunalabs.hmp.auth.shared.exception.UsernameAlreadyTakenException;
import io.vikunalabs.hmp.auth.user.domain.User;
import io.vikunalabs.hmp.auth.user.repository.UserRepository;
import io.vikunalabs.hmp.auth.user.service.UserService;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@RequiredArgsConstructor
@Service
@Transactional(readOnly = true)
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final Duration LOCKOUT_DURATION = Duration.ofMinutes(15);

    @Override
    public void validateUniqueUsernameAndEmail(String username, String email) {
        log.debug("Validating uniqueness for username: {} and email: {}", username, email);

        if (userRepository.existsByUsername(username)) {
            log.warn("Registration failed - username already taken: {}", username);
            throw UsernameAlreadyTakenException.withUsername(username);
        }

        if (userRepository.existsByEmail(email)) {
            log.warn("Registration failed - email already taken: {}", email);
            throw EmailAlreadyTakenException.withEmail(email);
        }

        log.debug("Username and email validation passed for: {} / {}", username, email);
    }

    @Override
    @Transactional
    @CacheEvict(value = "users", key = "#userId")
    public User enableUser(Long userId) {
        log.debug("Enabling user account for ID: {}", userId);

        User user = findById(userId);
        user.setAccountEnabled(true);
        user.setEmailVerified(true);

        User savedUser = save(user);
        log.info("Enabled user account for ID: {} with email: {}", userId, savedUser.getEmail());

        return savedUser;
    }

    @Override
    public User getUserReference(Long userId) {
        return userRepository.getReferenceById(userId);
    }

    @Override
    @Cacheable(value = "users", key = "#userId")
    public User findById(Long userId) {
        return userRepository.findById(userId).orElseThrow(() -> {
            log.warn("User not found with ID: {}", userId);
            return UserNotFoundException.withID(userId);
        });
    }

    @Override
    @Cacheable(value = "users", key = "#email")
    public User findByEmail(String email) {
        return userRepository.findByEmail(email).orElseThrow(() -> {
            log.warn("User not found with email: {}", email);
            return UserNotFoundException.withUsername(email);
        });
    }

    @Override
    public User findByUsername(String username) {
        return userRepository.findByUsername(username).orElseThrow(() -> {
            log.warn("User not found with username: {}", username);
            return UserNotFoundException.withUsername(username);
        });
    }

    @Override
    public User findByUsernameOrEmail(String usernameOrEmail) {
        log.debug("Looking for user with username or email: {}", usernameOrEmail);

        return userRepository
                .findByUsernameOrEmail(usernameOrEmail, usernameOrEmail)
                .orElseThrow(() -> {
                    log.warn("User not found with username or email: {}", usernameOrEmail);
                    return UserNotFoundException.withUsername(usernameOrEmail);
                });
    }

    @Override
    @Transactional
    @CacheEvict(value = "users", key = "#user.id")
    public User save(User user) {
        return userRepository.save(user);
    }

    @Override
    @Transactional
    public void recordFailedLoginAttempt(User user) {
        user.setFailedLoginAttempts(user.getFailedLoginAttempts() + 1);

        if (user.getFailedLoginAttempts() >= MAX_FAILED_ATTEMPTS) {
            user.setLockedUntil(Instant.now().plus(LOCKOUT_DURATION));
            user.setAccountLocked(true);
            log.warn("User account locked due to failed attempts: {}", user.getEmail());
        }

        save(user);
    }

    @Override
    @Transactional
    public void resetFailedLoginAttempts(User user) {
        user.setFailedLoginAttempts(0);
        user.setAccountLocked(false);
        user.setLockedUntil(null);
        save(user);
    }

    @Override
    public boolean isAccountLocked(User user) {
        return user.isAccountLocked()
                && (user.getLockedUntil() == null || Instant.now().isBefore(user.getLockedUntil()));
    }

    @Override
    public User findByProviderAndProviderId(String provider, String providerId) {
        return userRepository.findByProviderAndProviderId(provider, providerId).orElseThrow(() -> {
            log.warn("OAuth2 user not found with provider: {} and providerId: {}", provider, providerId);
            return UserNotFoundException.withUsernameAndEmail(provider, providerId);
        });
    }

    @Override
    public boolean existsByUsername(String username) {
        return userRepository.existsByUsername(username);
    }

    @Override
    public String generateUniqueUsername(String email) {
        String baseUsername = email.split("@")[0]
                .replaceAll("[^a-zA-Z0-9._-]", "") // Remove invalid characters
                .toLowerCase();

        // Ensure minimum length
        if (baseUsername.length() < 3) {
            baseUsername = "user" + baseUsername;
        }

        // Ensure maximum length
        if (baseUsername.length() > 15) {
            baseUsername = baseUsername.substring(0, 15);
        }

        String username = baseUsername;
        int counter = 1;

        while (existsByUsername(username)) {
            String suffix = String.valueOf(counter);
            int maxBaseLength = 15 - suffix.length();
            String truncatedBase =
                    baseUsername.length() > maxBaseLength ? baseUsername.substring(0, maxBaseLength) : baseUsername;
            username = truncatedBase + counter;
            counter++;

            // Prevent infinite loop
            if (counter > 1000) {
                username = "user" + UUID.randomUUID().toString().substring(0, 8);
                break;
            }
        }

        log.debug("Generated username: {} for email: {}", username, email);
        return username;
    }

    @Override
    public boolean isEmailTaken(String email) {
        return userRepository.existsByEmail(email);
    }
}
