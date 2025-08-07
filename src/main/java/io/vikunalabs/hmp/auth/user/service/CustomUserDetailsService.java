package io.vikunalabs.hmp.auth.user.service;

import io.vikunalabs.hmp.auth.user.domain.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Slf4j
@RequiredArgsConstructor
@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserService userService;

    @Override
    public UserDetails loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {
        log.debug("Attempting to load user by username or email: {}", usernameOrEmail);

        try {
            User user = userService.findByUsernameOrEmail(usernameOrEmail);

            // Check if account is locked and should be unlocked
            if (user.getLockedUntil() != null && Instant.now().isAfter(user.getLockedUntil())) {
                userService.resetFailedLoginAttempts(user);
                user = userService.findById(user.getId()); // Refresh user after reset
            }

            log.debug("Successfully loaded user: {} (ID: {})", user.getEmail(), user.getId());
            return new CustomUserDetails(user);

        } catch (Exception ex) {
            log.warn("Failed to load user with username/email: {}", usernameOrEmail);
            throw new UsernameNotFoundException("User not found with username or email: " + usernameOrEmail, ex);
        }
    }
}