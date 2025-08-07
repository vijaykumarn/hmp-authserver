package io.vikunalabs.hmp.auth.oauth2;

import io.vikunalabs.hmp.auth.shared.exception.*;
import io.vikunalabs.hmp.auth.user.domain.User;
import io.vikunalabs.hmp.auth.user.domain.UserRole;
import io.vikunalabs.hmp.auth.user.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserService userService;
    private final OAuth2RateLimitingService rateLimitingService;
    private final OAuth2AuditService auditService;

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oauth2User;
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        
        // Get request context for rate limiting and auditing
        HttpServletRequest request = getCurrentRequest();
        String clientIp = request != null ? auditService.getClientIP(request) : "unknown";
        String userAgent = request != null ? auditService.getUserAgent(request) : "unknown";
        
        log.info("OAuth2 login attempt with provider: {}", registrationId);
        
        try {
            oauth2User = super.loadUser(userRequest);
        } catch (Exception e) {
            log.error("Failed to load user from OAuth2 provider: {}", registrationId, e);
            auditService.logOAuth2Failure(registrationId, "unknown", "provider_error", clientIp, userAgent);
            throw new OAuth2AuthenticationException(
                new OAuth2Error("provider_error", "Failed to get user information from " + registrationId, null));
        }
        
        String email = (String) oauth2User.getAttributes().get("email");
        
        // Rate limiting
        try {
            rateLimitingService.checkOAuth2AttemptLimit(clientIp, email);
            if (email != null) {
                rateLimitingService.checkOAuth2EmailLimit(email);
            }
        } catch (TooManyRequestsException e) {
            auditService.logOAuth2RateLimit("oauth2_attempt", clientIp, clientIp);
            throw new OAuth2AuthenticationException(
                new OAuth2Error("rate_limit_exceeded", e.getMessage(), null));
        }
        
        auditService.logOAuth2Attempt(registrationId, email, clientIp, userAgent);
        
        try {
            User user = processOAuth2User(oauth2User, registrationId);
            boolean isNewUser = user.getCreatedAt().isAfter(user.getUpdatedAt().minusSeconds(5)); // Rough check
            
            auditService.logOAuth2Success(user, registrationId, clientIp, userAgent, isNewUser);
            rateLimitingService.clearOAuth2RateLimit(clientIp, email);
            
            return new OAuth2UserPrincipal(user, oauth2User.getAttributes());
        } catch (OAuth2EmailConflictException | OAuth2UserDataException | OAuth2ProviderException e) {
            log.warn("OAuth2 processing error: {}", e.getMessage());
            auditService.logOAuth2Failure(registrationId, email, e.getClass().getSimpleName(), clientIp, userAgent);
            throw new OAuth2AuthenticationException(
                new OAuth2Error("user_processing_error", e.getMessage(), null));
        } catch (Exception e) {
            log.error("Unexpected error processing OAuth2 user", e);
            auditService.logOAuth2Failure(registrationId, email, "internal_error", clientIp, userAgent);
            throw new OAuth2AuthenticationException(
                new OAuth2Error("internal_error", "An unexpected error occurred during sign-in", null));
        }
    }
    
    private HttpServletRequest getCurrentRequest() {
        try {
            ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
            return attributes.getRequest();
        } catch (Exception e) {
            return null;
        }
    }

    private User processOAuth2User(OAuth2User oauth2User, String provider) {
        // Validate provider
        if (!"google".equals(provider)) {
            throw OAuth2ProviderException.unsupportedProvider(provider);
        }
        
        Map<String, Object> attributes = oauth2User.getAttributes();
        
        // Extract and validate required fields
        String providerId = extractRequiredAttribute(attributes, "sub", "User ID");
        String email = extractRequiredAttribute(attributes, "email", "Email");
        
        // Validate email format
        if (!isValidEmail(email)) {
            throw OAuth2UserDataException.invalidEmailFormat(email);
        }
        
        String firstName = (String) attributes.get("given_name");
        String lastName = (String) attributes.get("family_name");
        
        log.debug("Processing OAuth2 user - Provider: {}, ProviderId: {}, Email: {}", 
                 provider, providerId, email);

        // Try to find existing user by provider and providerId
        try {
            User existingUser = userService.findByProviderAndProviderId(provider, providerId);
            log.info("Found existing OAuth2 user: {}", existingUser.getEmail());
            
            // Check if email has changed on the provider side
            if (!existingUser.getEmail().equals(email)) {
                log.warn("Email changed for OAuth2 user - Old: {}, New: {}", existingUser.getEmail(), email);
                // Update email if it changed on Google's side
                existingUser.setEmail(email);
                return userService.save(existingUser);
            }
            
            return existingUser;
        } catch (UserNotFoundException e) {
            log.debug("No existing OAuth2 user found, checking for email conflicts");
        }

        // Check if email is already taken by local account
        try {
            User existingEmailUser = userService.findByEmail(email);
            log.warn("Email {} already exists with provider: {}", email, existingEmailUser.getProvider());
            
            String existingProvider = "local".equals(existingEmailUser.getProvider()) ? 
                "email/password" : existingEmailUser.getProvider();
            throw OAuth2EmailConflictException.withEmail(email, existingProvider);
        } catch (UserNotFoundException e) {
            log.debug("Email not found, proceeding with user creation");
        }

        // Create new OAuth2 user
        return createOAuth2User(email, firstName, lastName, provider, providerId);
    }
    
    private String extractRequiredAttribute(Map<String, Object> attributes, String key, String fieldName) {
        Object value = attributes.get(key);
        if (value == null || !StringUtils.hasText(value.toString())) {
            throw OAuth2UserDataException.missingRequiredData(fieldName);
        }
        return value.toString();
    }
    
    private boolean isValidEmail(String email) {
        return StringUtils.hasText(email) && email.contains("@") && email.contains(".");
    }

    private User createOAuth2User(String email, String firstName, String lastName, 
                                 String provider, String providerId) {
        
        String username = generateUsername(email);
        
        User newUser = User.builder()
                .username(username)
                .email(email)
                .firstName(firstName)
                .lastName(lastName)
                .provider(provider)
                .providerId(providerId)
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

        User savedUser = userService.save(newUser);
        log.info("Created new OAuth2 user: {} with provider: {}", savedUser.getEmail(), provider);
        
        return savedUser;
    }

    private String generateUsername(String email) {
        String baseUsername = email.split("@")[0];
        String username = baseUsername;
        int counter = 1;
        
        while (userService.existsByUsername(username)) {
            username = baseUsername + counter;
            counter++;
        }
        
        log.debug("Generated username: {} for email: {}", username, email);
        return username;
    }
}