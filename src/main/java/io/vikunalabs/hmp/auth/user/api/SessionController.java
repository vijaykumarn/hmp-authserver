package io.vikunalabs.hmp.auth.user.api;

import io.vikunalabs.hmp.auth.shared.ApiResponse;
import io.vikunalabs.hmp.auth.user.domain.SessionInfo;
import io.vikunalabs.hmp.auth.user.service.CustomUserDetails;
import io.vikunalabs.hmp.auth.user.service.SessionService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RequiredArgsConstructor
@RestController
@RequestMapping("/api/session")
public class SessionController {

    private final SessionService sessionService;

    @GetMapping("/info")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ApiResponse<SessionInfo>> getSessionInfo(HttpServletRequest request) {
        SessionInfo sessionInfo = sessionService.getCurrentSessionInfo(request);
        return ResponseEntity.ok(new ApiResponse<>(true, sessionInfo));
    }

    @GetMapping("/all")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ApiResponse<List<SessionInfo>>> getAllUserSessions(Authentication authentication) {
        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        List<SessionInfo> sessions = sessionService.getUserActiveSessions(userDetails.getUserId());
        return ResponseEntity.ok(new ApiResponse<>(true, sessions));
    }

    @PostMapping("/invalidate-all")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ApiResponse<String>> invalidateAllSessions(
            Authentication authentication, HttpServletRequest request, HttpServletResponse response) {

        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        sessionService.invalidateAllUserSessions(userDetails.getUserId());

        // Invalidate current session as well
        sessionService.invalidateSession(request, response);

        return ResponseEntity.ok(new ApiResponse<>(true, "All sessions have been invalidated. Please log in again."));
    }

    // FIXED: Change to GET method and remove @PreAuthorize for OAuth2 callback validation
    @GetMapping("/validate")
    public ResponseEntity<ApiResponse<Map<String, Object>>> validateSession(
            HttpServletRequest request, Authentication authentication) {

        log.info("Session validation request from: {}", request.getRemoteAddr());
        log.info("Authentication present: {}", authentication != null);
        log.info("Authentication authenticated: {}", authentication != null ? authentication.isAuthenticated() : false);

        // Check if user is authenticated
        boolean isAuthenticated = authentication != null
                && authentication.isAuthenticated()
                && !"anonymousUser".equals(authentication.getPrincipal());

        if (!isAuthenticated) {
            log.warn("Session validation failed - user not authenticated");
            return ResponseEntity.ok(
                    new ApiResponse<>(false, Map.of("authenticated", false, "reason", "not_authenticated")));
        }

        // Validate session security
        boolean isValid = sessionService.validateSessionSecurity(request);

        Map<String, Object> validationResult = Map.of(
                "authenticated",
                isAuthenticated,
                "valid",
                isValid,
                "userId",
                getUserId(authentication),
                "email",
                getUserEmail(authentication));

        log.info("Session validation result: {}", validationResult);

        return ResponseEntity.ok(new ApiResponse<>(true, validationResult));
    }

    // NEW: Add a simple session check endpoint that doesn't require authentication
    @GetMapping("/check")
    public ResponseEntity<ApiResponse<Map<String, Object>>> checkSession(
            HttpServletRequest request, Authentication authentication) {

        HttpSession session = request.getSession(false);
        boolean hasSession = session != null;
        boolean isAuthenticated = authentication != null
                && authentication.isAuthenticated()
                && !"anonymousUser".equals(authentication.getPrincipal());

        Map<String, Object> sessionCheck = Map.of(
                "hasSession",
                hasSession,
                "sessionId",
                hasSession ? session.getId() : "none",
                "authenticated",
                isAuthenticated,
                "principal",
                authentication != null
                        ? authentication.getPrincipal().getClass().getSimpleName()
                        : "none");

        log.info("Session check result: {}", sessionCheck);

        return ResponseEntity.ok(new ApiResponse<>(true, sessionCheck));
    }

    private Long getUserId(Authentication authentication) {
        if (authentication.getPrincipal() instanceof CustomUserDetails userDetails) {
            return userDetails.getUserId();
        }
        return null;
    }

    private String getUserEmail(Authentication authentication) {
        if (authentication.getPrincipal() instanceof CustomUserDetails userDetails) {
            return userDetails.getEmail();
        }
        return null;
    }
}
