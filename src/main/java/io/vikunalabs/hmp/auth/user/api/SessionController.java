package io.vikunalabs.hmp.auth.user.api;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
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
import org.springframework.web.bind.annotation.*;

@Slf4j
@RequiredArgsConstructor
@RestController
@RequestMapping("/api/session")
@Tag(name = "session", description = "Session management")
@SecurityRequirement(name = "cookieAuth")
public class SessionController {

    private final SessionService sessionService;

    @GetMapping("/info")
    @PreAuthorize("isAuthenticated()")
    @Operation(
            summary = "Get current session info",
            description = "Get information about the current user session",
            responses = {
                @ApiResponse(
                        responseCode = "200",
                        description = "Session information retrieved",
                        content =
                                @Content(
                                        mediaType = "application/json",
                                        schema =
                                                @Schema(
                                                        implementation =
                                                                io.vikunalabs.hmp.auth.shared.ApiResponse.class),
                                        examples = {
                                            @ExampleObject(
                                                    name = "success",
                                                    summary = "Session info",
                                                    value =
                                                            """
                            {
                              "success": true,
                              "data": {
                                "sessionId": "sess_123456789",
                                "userId": 12345,
                                "userEmail": "john.doe@example.com",
                                "ipAddress": "192.168.1.1",
                                "userAgent": "Mozilla/5.0...",
                                "createdAt": "2025-08-12T10:00:00Z",
                                "lastAccessedAt": "2025-08-12T10:30:00Z",
                                "rememberMe": true,
                                "valid": true
                              }
                            }
                            """)
                                        })),
                @ApiResponse(
                        responseCode = "401",
                        description = "Not authenticated",
                        content =
                                @Content(
                                        mediaType = "application/json",
                                        schema =
                                                @Schema(
                                                        implementation =
                                                                io.vikunalabs.hmp.auth.shared.ApiResponse.class)))
            })
    public ResponseEntity<io.vikunalabs.hmp.auth.shared.ApiResponse<SessionInfo>> getSessionInfo(
            HttpServletRequest request) {
        SessionInfo sessionInfo = sessionService.getCurrentSessionInfo(request);
        return ResponseEntity.ok(new io.vikunalabs.hmp.auth.shared.ApiResponse<>(true, sessionInfo));
    }

    @GetMapping("/all")
    @PreAuthorize("isAuthenticated()")
    @Operation(
            summary = "Get all user sessions",
            description = "Get all active sessions for the current user",
            responses = {
                @ApiResponse(
                        responseCode = "200",
                        description = "User sessions retrieved",
                        content =
                                @Content(
                                        mediaType = "application/json",
                                        schema =
                                                @Schema(
                                                        implementation =
                                                                io.vikunalabs.hmp.auth.shared.ApiResponse.class),
                                        examples = {
                                            @ExampleObject(
                                                    name = "success",
                                                    summary = "All sessions",
                                                    value =
                                                            """
                            {
                              "success": true,
                              "data": [
                                {
                                  "sessionId": "sess_123456789",
                                  "userId": 12345,
                                  "userEmail": "john.doe@example.com",
                                  "ipAddress": "192.168.1.1",
                                  "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                                  "createdAt": "2025-08-12T10:00:00Z",
                                  "lastAccessedAt": "2025-08-12T10:30:00Z",
                                  "rememberMe": true,
                                  "valid": true
                                },
                                {
                                  "sessionId": "sess_987654321",
                                  "userId": 12345,
                                  "userEmail": "john.doe@example.com",
                                  "ipAddress": "192.168.1.2",
                                  "userAgent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)",
                                  "createdAt": "2025-08-11T15:00:00Z",
                                  "lastAccessedAt": "2025-08-11T20:00:00Z",
                                  "rememberMe": false,
                                  "valid": true
                                }
                              ]
                            }
                            """)
                                        })),
                @ApiResponse(
                        responseCode = "401",
                        description = "Not authenticated",
                        content =
                                @Content(
                                        mediaType = "application/json",
                                        schema =
                                                @Schema(
                                                        implementation =
                                                                io.vikunalabs.hmp.auth.shared.ApiResponse.class)))
            })
    public ResponseEntity<io.vikunalabs.hmp.auth.shared.ApiResponse<List<SessionInfo>>> getAllUserSessions(
            Authentication authentication) {
        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        List<SessionInfo> sessions = sessionService.getUserActiveSessions(userDetails.getUserId());
        return ResponseEntity.ok(new io.vikunalabs.hmp.auth.shared.ApiResponse<>(true, sessions));
    }

    @DeleteMapping("/invalidate/{sessionId}")
    @PreAuthorize("isAuthenticated()")
    @Operation(
            summary = "Invalidate specific session",
            description = "Invalidate a specific user session",
            parameters = {
                @Parameter(
                        name = "sessionId",
                        in = ParameterIn.PATH,
                        required = true,
                        description = "Session ID to invalidate",
                        schema = @Schema(type = "string"),
                        example = "sess_123456789")
            },
            responses = {
                @ApiResponse(
                        responseCode = "200",
                        description = "Session invalidated successfully",
                        content =
                                @Content(
                                        mediaType = "application/json",
                                        schema =
                                                @Schema(
                                                        implementation =
                                                                io.vikunalabs.hmp.auth.shared.ApiResponse.class))),
                @ApiResponse(
                        responseCode = "401",
                        description = "Not authenticated",
                        content =
                                @Content(
                                        mediaType = "application/json",
                                        schema =
                                                @Schema(
                                                        implementation =
                                                                io.vikunalabs.hmp.auth.shared.ApiResponse.class))),
                @ApiResponse(
                        responseCode = "404",
                        description = "Session not found",
                        content =
                                @Content(
                                        mediaType = "application/json",
                                        schema =
                                                @Schema(
                                                        implementation =
                                                                io.vikunalabs.hmp.auth.shared.ApiResponse.class)))
            })
    public ResponseEntity<io.vikunalabs.hmp.auth.shared.ApiResponse<String>> invalidateSession(
            @PathVariable String sessionId, Authentication authentication) {

        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        // TODO
        // sessionService.invalidateSession(userDetails.getUserId(), sessionId);

        return ResponseEntity.ok(
                new io.vikunalabs.hmp.auth.shared.ApiResponse<>(true, "Session invalidated successfully"));
    }

    @PostMapping("/invalidate-all")
    @PreAuthorize("isAuthenticated()")
    @Operation(
            summary = "Invalidate all sessions",
            description = "Invalidate all user sessions except current one",
            responses = {
                @ApiResponse(
                        responseCode = "200",
                        description = "All sessions invalidated successfully",
                        content =
                                @Content(
                                        mediaType = "application/json",
                                        schema =
                                                @Schema(
                                                        implementation =
                                                                io.vikunalabs.hmp.auth.shared.ApiResponse.class),
                                        examples = {
                                            @ExampleObject(
                                                    name = "success",
                                                    summary = "Sessions invalidated",
                                                    value =
                                                            """
                            {
                              "success": true,
                              "data": "All other sessions invalidated",
                              "message": "Successfully logged out from all other devices"
                            }
                            """)
                                        })),
                @ApiResponse(
                        responseCode = "401",
                        description = "Not authenticated",
                        content =
                                @Content(
                                        mediaType = "application/json",
                                        schema =
                                                @Schema(
                                                        implementation =
                                                                io.vikunalabs.hmp.auth.shared.ApiResponse.class)))
            })
    public ResponseEntity<io.vikunalabs.hmp.auth.shared.ApiResponse<String>> invalidateAllSessions(
            Authentication authentication, HttpServletRequest request, HttpServletResponse response) {

        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        sessionService.invalidateAllUserSessions(userDetails.getUserId());

        // Invalidate current session as well
        sessionService.invalidateSession(request, response);

        return ResponseEntity.ok(new io.vikunalabs.hmp.auth.shared.ApiResponse<>(
                true, "All sessions have been invalidated. Please log in again."));
    }

    @GetMapping("/validate")
    @Operation(
            summary = "Validate session",
            description = "Check if current session is valid",
            responses = {
                @ApiResponse(
                        responseCode = "200",
                        description = "Session validation result",
                        content =
                                @Content(
                                        mediaType = "application/json",
                                        schema =
                                                @Schema(
                                                        implementation =
                                                                io.vikunalabs.hmp.auth.shared.ApiResponse.class),
                                        examples = {
                                            @ExampleObject(
                                                    name = "valid",
                                                    summary = "Valid session",
                                                    value =
                                                            """
                            {
                              "success": true,
                              "data": {
                                "valid": true,
                                "userId": 12345,
                                "expiresAt": "2025-08-13T10:00:00Z"
                              }
                            }
                            """),
                                            @ExampleObject(
                                                    name = "invalid",
                                                    summary = "Invalid session",
                                                    value =
                                                            """
                            {
                              "success": false,
                              "data": {
                                "valid": false,
                                "reason": "Session expired"
                              }
                            }
                            """)
                                        }))
            })
    public ResponseEntity<io.vikunalabs.hmp.auth.shared.ApiResponse<Map<String, Object>>> validateSession(
            HttpServletRequest request, Authentication authentication) {

        log.info("Session validation request from: {}", request.getRemoteAddr());
        log.info("Authentication present: {}", authentication != null);
        log.info("Authentication authenticated: {}", authentication != null && authentication.isAuthenticated());

        // Check if user is authenticated
        boolean isAuthenticated = authentication != null
                && authentication.isAuthenticated()
                && !"anonymousUser".equals(authentication.getPrincipal());

        if (!isAuthenticated) {
            log.warn("Session validation failed - user not authenticated");
            return ResponseEntity.ok(new io.vikunalabs.hmp.auth.shared.ApiResponse<>(
                    false, Map.of("authenticated", false, "reason", "not_authenticated")));
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

        return ResponseEntity.ok(new io.vikunalabs.hmp.auth.shared.ApiResponse<>(true, validationResult));
    }

    @GetMapping("/check")
    @Operation(
            summary = "Basic session check",
            description = "Performs a lightweight check for session existence without validation",
            responses = {
                @ApiResponse(
                        responseCode = "200",
                        description = "Session check result",
                        content =
                                @Content(
                                        mediaType = "application/json",
                                        schema =
                                                @Schema(
                                                        implementation =
                                                                io.vikunalabs.hmp.auth.shared.ApiResponse.class),
                                        examples = {
                                            @ExampleObject(
                                                    name = "authenticated_session",
                                                    summary = "Authenticated session exists",
                                                    value =
                                                            """
                        {
                          "success": true,
                          "data": {
                            "hasSession": true,
                            "sessionId": "ABC123",
                            "authenticated": true,
                            "principal": "CustomUserDetails",
                            "userId": 12345,
                            "email": "user@example.com"
                          }
                        }
                        """),
                                            @ExampleObject(
                                                    name = "unauthenticated_session",
                                                    summary = "Unauthenticated session exists",
                                                    value =
                                                            """
                        {
                          "success": true,
                          "data": {
                            "hasSession": true,
                            "sessionId": "ABC123",
                            "authenticated": false,
                            "principal": "none"
                          }
                        }
                        """),
                                            @ExampleObject(
                                                    name = "no_session",
                                                    summary = "No session exists",
                                                    value =
                                                            """
                        {
                          "success": true,
                          "data": {
                            "hasSession": false,
                            "sessionId": "none",
                            "authenticated": false,
                            "principal": "none"
                          }
                        }
                        """)
                                        }))
            })
    public ResponseEntity<io.vikunalabs.hmp.auth.shared.ApiResponse<Map<String, Object>>> checkSession(
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

        // Add user details if authenticated
        if (isAuthenticated) {
            CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
            sessionCheck.put("userId", userDetails.getUserId());
            sessionCheck.put("email", userDetails.getEmail());
        }

        log.debug("Session check performed - hasSession: {}, authenticated: {}", hasSession, isAuthenticated);

        return ResponseEntity.ok(new io.vikunalabs.hmp.auth.shared.ApiResponse<>(true, sessionCheck));
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
