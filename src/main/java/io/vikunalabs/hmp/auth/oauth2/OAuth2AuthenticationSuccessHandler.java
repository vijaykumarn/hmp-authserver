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
        
        OAuth2UserPrincipal principal = (OAuth2UserPrincipal) authentication.getPrincipal();
        User user = principal.getUser();
        
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