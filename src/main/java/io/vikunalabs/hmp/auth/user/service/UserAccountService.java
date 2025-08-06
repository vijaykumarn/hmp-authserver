package io.vikunalabs.hmp.auth.user.service;

import io.vikunalabs.hmp.auth.user.domain.UserAccount;

public interface UserAccountService {

    UserAccount findById(Long id);

    UserAccount findByEmail(String email);

    UserAccount save(UserAccount userAccount);

    void validateUniqueUsernameAndEmail(String username, String email);

    UserAccount enableUserAccount(Long userId);

    UserAccount getUserAccountReference(Long userId);

    UserAccount getByUsernameOrEmail(String username, String email);
}
