package io.vikunalabs.hmp.auth.oauth2;

import io.vikunalabs.hmp.auth.shared.exception.*;
import io.vikunalabs.hmp.auth.user.domain.User;
import io.vikunalabs.hmp.auth.user.domain.UserRole;
import io.vikunalabs.hmp.auth.user.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import jakarta.servlet.http.HttpServletRequest;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@Slf4j
@RequiredArgsConstructor
@Service
public class CustomOidcUserService extends OidcUserService {

    private final UserService userService;
    private final OAuth2RateLimitingService rateLimitingService;
    private final OAuth2AuditService auditService;

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        log.info("=== CustomOidcUserService.loadUser() CALLED ===");

        // First, get the user from Google
        OidcUser oidcUser = super.loadUser(userRequest);
        log.info("OIDC user loaded - subject: {}, email: {}", oidcUser.getSubject(), oidcUser.getEmail());

        // Process our user (create if needed)
        processOidcUser(oidcUser, userRequest.getClientRegistration().getRegistrationId());

        // Return the original OIDC user - Spring Security will handle it properly
        log.info("=== RETURNING original OidcUser ===");
        return oidcUser;
    }

    @Transactional
    protected void processOidcUser(OidcUser oidcUser, String provider) {
        log.info("=== processOidcUser START ===");

        if (!"google".equals(provider)) {
            throw OAuth2ProviderException.unsupportedProvider(provider);
        }

        String providerId = oidcUser.getSubject();
        String email = oidcUser.getEmail();
        String firstName = oidcUser.getGivenName();
        String lastName = oidcUser.getFamilyName();

        log.info("Processing OIDC user - providerId: {}, email: {}", providerId, email);

        // Try to find existing user
        try {
            User existingUser = userService.findByProviderAndProviderId(provider, providerId);
            log.info("Found existing user: {}", existingUser.getEmail());
            return; // User already exists, nothing to do
        } catch (UserNotFoundException e) {
            log.info("User not found, will create new user");
        }

        // Check for email conflicts
        try {
            User existingEmailUser = userService.findByEmail(email);
            log.warn("Email {} already exists with provider: {}", email, existingEmailUser.getProvider());
            String existingProvider = "local".equals(existingEmailUser.getProvider()) ?
                    "email/password" : existingEmailUser.getProvider();
            throw OAuth2EmailConflictException.withEmail(email, existingProvider);
        } catch (UserNotFoundException e) {
            log.info("Email available, proceeding with user creation");
        }

        // Create new user
        String username = generateUsername(email);
        User newUser = User.builder()
                .username(username)
                .email(email)
                .password("") // Empty for OAuth users
                .firstName(firstName)
                .lastName(lastName)
                .provider(provider)
                .providerId(providerId)
                .role(UserRole.USER)
                .accountEnabled(true)
                .emailVerified(true)
                .credentialsExpired(false)
                .accountExpired(false)
                .accountLocked(false)
                .failedLoginAttempts(0)
                .consent(true)
                .notification(false)
                .build();

        User savedUser = userService.save(newUser);
        log.info("Created new OIDC user with ID: {} and email: {}", savedUser.getId(), savedUser.getEmail());
    }

    private String generateUsername(String email) {
        String baseUsername = email.split("@")[0];
        String username = baseUsername;
        int counter = 1;

        while (userService.existsByUsername(username)) {
            username = baseUsername + counter++;
        }

        return username;
    }
}