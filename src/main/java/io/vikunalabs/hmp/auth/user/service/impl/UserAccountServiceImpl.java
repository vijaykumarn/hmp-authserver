package io.vikunalabs.hmp.auth.user.service.impl;

import io.vikunalabs.hmp.auth.shared.exception.EmailAlreadyTakenException;
import io.vikunalabs.hmp.auth.shared.exception.UserNotFoundException;
import io.vikunalabs.hmp.auth.shared.exception.UsernameAlreadyTakenException;
import io.vikunalabs.hmp.auth.user.domain.UserAccount;
import io.vikunalabs.hmp.auth.user.repository.UserAccountRepository;
import io.vikunalabs.hmp.auth.user.service.UserAccountService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@RequiredArgsConstructor
@Service
@Transactional(readOnly = true)
public class UserAccountServiceImpl implements UserAccountService {

    private final UserAccountRepository accountRepository;

    @Override
    public void validateUniqueUsernameAndEmail(String username, String email) {
        log.debug("Validating uniqueness for username: {} and email: {}", username, email);

        // Check if username exists
        if (accountRepository.existsByUsername(username)) {
            log.warn("Registration failed - username already taken: {}", username);
            throw UsernameAlreadyTakenException.withUsername(username);
        }

        // Check if email exists
        if (accountRepository.existsByEmail(email)) {
            log.warn("Registration failed - email already taken: {}", email);
            throw EmailAlreadyTakenException.withEmail(email);
        }

        log.debug("Username and email validation passed for: {} / {}", username, email);
    }

    @Override
    @Transactional
    public UserAccount enableUserAccount(Long userId) {
        log.debug("Enabling user account for ID: {}", userId);

        UserAccount userAccount = findById(userId);
        userAccount.setAccountEnabled(true);
        userAccount.setEmailVerified(true);

        UserAccount savedAccount = save(userAccount);
        log.info("Enabled user account for ID: {} with email: {}", userId, savedAccount.getEmail());

        return savedAccount;
    }

    @Override
    public UserAccount getUserAccountReference(Long userId) {
        // Using reference for performance - no DB hit until accessed
        return accountRepository.getReferenceById(userId);
    }

    @Override
    public UserAccount findById(Long userId) {
        return accountRepository.findById(userId)
                .orElseThrow(() -> {
                    log.warn("User not found with ID: {}", userId);
                    return UserNotFoundException.withID(userId);
                });
    }

    @Override
    public UserAccount findByEmail(String email) {
        return accountRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.warn("User not found with email: {}", email);
                    return UserNotFoundException.withUsername(email);
                });
    }

    @Override
    @Transactional
    public UserAccount save(UserAccount userAccount) {
        return accountRepository.save(userAccount);
    }

    @Override
    public UserAccount getByUsernameOrEmail(String username, String email) {
        return accountRepository.getByUsernameAndEmail(username, email).orElseThrow(() -> UserNotFoundException.withUsernameAndEmail(username, email));
    }
}