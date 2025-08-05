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

@Slf4j
@RequiredArgsConstructor
@Service
public class UserAccountServiceImpl implements UserAccountService {

    private final UserAccountRepository accountRepository;

    @Override
    public void validateUniqueUsernameAndEmail(String username, String email) {

        accountRepository.findByUsernameOrEmail(username, email).ifPresent(existing -> {
            if (username.equals(existing.username())) {
                log.warn("Registration failed - username already taken: {}", username);
                throw UsernameAlreadyTakenException.withUsername(username);
            }
            if (email.equals(existing.email())) {
                log.warn("Registration failed - email already taken: {}", email);
                throw EmailAlreadyTakenException.withEmail(email);
            }
        });
    }

    @Override
    public UserAccount enableUserAccount(Long userId) {
        UserAccount userAccount = findById(userId);
        userAccount.setAccountEnabled(true);
        userAccount.setEmailVerified(true);
        return save(userAccount);
    }

    @Override
    public UserAccount getUserAccountReference(Long userId) {
        return accountRepository.getReferenceById(userId);
    }

    @Override
    public UserAccount findById(Long userId) {
        return accountRepository.findById(userId).orElseThrow(() -> UserNotFoundException.withID(userId));
    }

    @Override
    public UserAccount findByEmail(String email) {
        return accountRepository.findByEmail(email).orElseThrow(() -> UserNotFoundException.withUsername(email));
    }

    @Override
    public UserAccount save(UserAccount userAccount) {
        return accountRepository.save(userAccount);
    }
}
