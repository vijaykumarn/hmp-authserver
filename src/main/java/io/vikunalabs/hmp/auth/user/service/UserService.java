package io.vikunalabs.hmp.auth.user.service;

import io.vikunalabs.hmp.auth.user.domain.User;

public interface UserService {
    
    User findById(Long id);
    
    User findByEmail(String email);
    
    User findByUsername(String username);
    
    User findByUsernameOrEmail(String usernameOrEmail);
    
    User save(User user);
    
    void validateUniqueUsernameAndEmail(String username, String email);
    
    User enableUser(Long userId);
    
    User getUserReference(Long userId);
    
    void recordFailedLoginAttempt(User user);
    
    void resetFailedLoginAttempts(User user);
    
    boolean isAccountLocked(User user);

    // New methods for OAuth2 support
    User findByProviderAndProviderId(String provider, String providerId);

    boolean existsByUsername(String username);
}