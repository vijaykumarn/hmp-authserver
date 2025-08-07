package io.vikunalabs.hmp.auth.oauth2;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Slf4j
@Component
public class OAuth2AuthenticationFailureHandler implements AuthenticationFailureHandler {

    @Value("${app.oauth2.failure-redirect-url:http://localhost:5173/login}")
    private String failureRedirectUrl;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {

        String errorCode = "oauth2_error";
        String errorMessage = "OAuth2 authentication failed";

        if (exception instanceof OAuth2AuthenticationException oauth2Exception) {
            errorCode = oauth2Exception.getError().getErrorCode();
            errorMessage = getUserFriendlyMessage(oauth2Exception);

            log.warn("OAuth2 authentication failed: {} - {}", errorCode, errorMessage);
        } else {
            log.error("OAuth2 authentication failed with unexpected error", exception);
        }

        // Redirect to frontend login page with error
        String redirectUrl = buildErrorRedirectUrl(errorCode, errorMessage);
        response.sendRedirect(redirectUrl);
    }

    private String getUserFriendlyMessage(OAuth2AuthenticationException ex) {
        String errorCode = ex.getError().getErrorCode();

        return switch (errorCode) {
            case "access_denied" -> "Sign-in was cancelled";
            case "user_processing_error" -> ex.getError().getDescription();
            case "provider_error" -> "Unable to connect to Google. Please try again.";
            case "internal_error" -> "An unexpected error occurred. Please try again.";
            default -> "Sign-in with Google failed. Please try again.";
        };
    }

    private String buildErrorRedirectUrl(String errorCode, String errorMessage) {
        String encodedError = URLEncoder.encode(errorCode, StandardCharsets.UTF_8);
        String encodedMessage = URLEncoder.encode(errorMessage, StandardCharsets.UTF_8);

        return String.format("%s?error=%s&message=%s", failureRedirectUrl, encodedError, encodedMessage);
    }
}