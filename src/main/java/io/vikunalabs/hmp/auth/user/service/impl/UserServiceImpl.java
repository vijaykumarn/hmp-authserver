package io.vikunalabs.hmp.auth.user.service.impl;

import io.vikunalabs.hmp.auth.shared.exception.EmailAlreadyTakenException;
import io.vikunalabs.hmp.auth.shared.exception.UserNotFoundException;
import io.vikunalabs.hmp.auth.shared.exception.UsernameAlreadyTakenException;
import io.vikunalabs.hmp.auth.user.domain.User;
import io.vikunalabs.hmp.auth.user.repository.UserRepository;
import io.vikunalabs.hmp.auth.user.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;

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
        return userRepository.findById(userId)
                .orElseThrow(() -> {
                    log.warn("User not found with ID: {}", userId);
                    return UserNotFoundException.withID(userId);
                });
    }

    @Override
    @Cacheable(value = "users", key = "#email")
    public User findByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.warn("User not found with email: {}", email);
                    return UserNotFoundException.withUsername(email);
                });
    }

    @Override
    public User findByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> {
                    log.warn("User not found with username: {}", username);
                    return UserNotFoundException.withUsername(username);
                });
    }

    @Override
    public User findByUsernameOrEmail(String usernameOrEmail) {
        log.debug("Looking for user with username or email: {}", usernameOrEmail);

        return userRepository.findByUsernameOrEmail(usernameOrEmail, usernameOrEmail)
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
        return user.isAccountLocked() && 
               (user.getLockedUntil() == null || Instant.now().isBefore(user.getLockedUntil()));
    }
}