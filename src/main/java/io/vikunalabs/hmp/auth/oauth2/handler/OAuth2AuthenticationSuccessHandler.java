package io.vikunalabs.hmp.auth.oauth2.handler;

import io.vikunalabs.hmp.auth.oauth2.domain.principal.CustomOidcUserPrincipal;
import io.vikunalabs.hmp.auth.oauth2.domain.principal.OAuth2UserPrincipal;
import io.vikunalabs.hmp.auth.shared.config.OAuth2ConfigProperties;
import io.vikunalabs.hmp.auth.user.domain.User;
import io.vikunalabs.hmp.auth.user.service.SessionService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

@Slf4j
@RequiredArgsConstructor
@Component
public class OAuth2AuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final SessionService sessionService;
    private final OAuth2ConfigProperties config;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException {

        log.info("OAuth2 authentication success handler called");
        log.info(
                "Authentication principal type: {}",
                authentication.getPrincipal().getClass().getName());

        try {
            // Extract user from either type of custom principal
            User user = extractUser(authentication);
            String provider = extractProvider(authentication);
            boolean isNewUser = isNewUser(user);

            log.info(
                    "OAuth2 authentication successful for user: {} with ID: {} (provider: {}, new: {})",
                    user.getEmail(),
                    user.getId(),
                    provider,
                    isNewUser);

            // Create session
            sessionService.createSession(user, false, request, response);
            log.info("Created session for OAuth2 user: {} (ID: {})", user.getEmail(), user.getId());

            // Determine redirect URL based on whether user is new
            String redirectUrl = determineRedirectUrl(isNewUser);
            response.sendRedirect(redirectUrl);

        } catch (Exception e) {
            log.error("Error in OAuth2 success handler", e);
            handleError(response, "session_creation_failed");
        }
    }

    private User extractUser(Authentication authentication) {
        Object principal = authentication.getPrincipal();

        // Handle CustomOidcUserPrincipal (from OIDC providers like Google)
        if (principal instanceof CustomOidcUserPrincipal oidcPrincipal) {
            return oidcPrincipal.getUser();
        }

        // Handle OAuth2UserPrincipal (from pure OAuth2 providers like GitHub)
        if (principal instanceof OAuth2UserPrincipal oauth2Principal) {
            return oauth2Principal.getUser();
        }

        // This should not happen with our setup
        log.error(
                "Unexpected authentication principal type: {}",
                principal.getClass().getName());
        throw new IllegalStateException(
                "Unexpected principal type: " + principal.getClass().getName());
    }

    private String extractProvider(Authentication authentication) {
        // Could extract from authentication details, but for now return based on principal type
        Object principal = authentication.getPrincipal();
        if (principal instanceof CustomOidcUserPrincipal) {
            return "google"; // OIDC is typically Google in our setup
        }
        return "oauth2"; // Generic OAuth2 provider
    }

    private boolean isNewUser(User user) {
        // Consider user "new" if created within last 5 seconds
        return user.getCreatedAt().isAfter(user.getUpdatedAt().minusSeconds(5));
    }

    private String determineRedirectUrl(boolean isNewUser) {
        String baseUrl = config.getSuccessRedirectUrl();
        if (isNewUser) {
            // Could redirect new users to onboarding or welcome page
            return baseUrl + "?welcome=true";
        }
        return baseUrl;
    }

    private void handleError(HttpServletResponse response, String errorCode) throws IOException {
        String errorUrl = String.format(
                "%s?error=%s", config.getFailureRedirectUrl(), URLEncoder.encode(errorCode, StandardCharsets.UTF_8));
        response.sendRedirect(errorUrl);
    }
}
