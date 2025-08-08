package io.vikunalabs.hmp.auth.user.api;

import io.vikunalabs.hmp.auth.shared.ApiResponse;
import io.vikunalabs.hmp.auth.user.domain.SessionInfo;
import io.vikunalabs.hmp.auth.user.service.CustomUserDetails;
import io.vikunalabs.hmp.auth.user.service.SessionService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.List;
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

    @PostMapping("/validate")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ApiResponse<Boolean>> validateSession(HttpServletRequest request) {
        boolean isValid = sessionService.validateSessionSecurity(request);
        return ResponseEntity.ok(new ApiResponse<>(true, isValid));
    }
}
