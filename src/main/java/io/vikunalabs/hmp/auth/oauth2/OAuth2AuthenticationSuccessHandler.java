package io.vikunalabs.hmp.auth.oauth2;

import io.vikunalabs.hmp.auth.user.domain.User;
import io.vikunalabs.hmp.auth.user.service.SessionService;
import io.vikunalabs.hmp.auth.user.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Slf4j
@RequiredArgsConstructor
@Component
public class OAuth2AuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final SessionService sessionService;
    private final UserService userService;

    @Value("${app.oauth2.success-redirect-url:http://localhost:5173/dashboard}")
    private String successRedirectUrl;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        User user = null;
        String userEmail = null;

        // Handle both OAuth2UserPrincipal and OidcUser (Google uses OidcUser)
        if (authentication.getPrincipal() instanceof OAuth2UserPrincipal principal) {
            user = principal.getUser();
            userEmail = user.getEmail();
        } else if (authentication.getPrincipal() instanceof OidcUser oidcUser) {
            // Extract user info from OidcUser
            userEmail = oidcUser.getEmail();
            String providerId = oidcUser.getSubject();

            try {
                // Find the user that was created/updated by CustomOAuth2UserService
                user = userService.findByProviderAndProviderId("google", providerId);
            } catch (Exception e) {
                log.error("Could not find user for OIDC subject: {}", providerId, e);
            }
        } else {
            log.error("Unexpected authentication principal type: {}",
                    authentication.getPrincipal().getClass().getName());
            String errorUrl = buildErrorRedirectUrl("unsupported_principal_type");
            response.sendRedirect(errorUrl);
            return;
        }

        if (user == null) {
            log.error("Could not extract user from OAuth2 authentication for email: {}", userEmail);
            String errorUrl = buildErrorRedirectUrl("user_extraction_failed");
            response.sendRedirect(errorUrl);
            return;
        }

        log.info("OAuth2 authentication successful for user: {}", user.getEmail());

        try {
            // Create session using existing session service
            sessionService.createSession(user, false, request, response);

            // Update last login
            sessionService.updateLastLogin(user);

            log.info("Created session for OAuth2 user: {} (ID: {})", user.getEmail(), user.getId());

            // Redirect to frontend success page
            response.sendRedirect(successRedirectUrl);

        } catch (Exception e) {
            log.error("Error creating session for OAuth2 user: {}", user.getEmail(), e);

            // Redirect to frontend with error
            String errorUrl = buildErrorRedirectUrl("session_creation_failed");
            response.sendRedirect(errorUrl);
        }
    }

    private String buildErrorRedirectUrl(String errorCode) {
        String errorParam = URLEncoder.encode(errorCode, StandardCharsets.UTF_8);
        return "http://localhost:5173/login?error=" + errorParam;
    }
}