package io.vikunalabs.hmp.auth.user.api;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/api/v1/security")
@Tag(name = "security", description = "Security and CSRF operations")
public class CsrfController {

    @GetMapping("/csrf-token")
    @Operation(
            summary = "Get CSRF token",
            description =
                    "Retrieves CSRF token information for form submissions. Required for all state-changing requests.",
            responses = {
                @ApiResponse(
                        responseCode = "200",
                        description = "CSRF token retrieved successfully",
                        content =
                                @Content(
                                        mediaType = "application/json",
                                        schema = @Schema(implementation = ApiResponse.class),
                                        examples = {
                                            @ExampleObject(
                                                    name = "success",
                                                    summary = "Successful CSRF token response",
                                                    value =
                                                            """
                            {
                              "success": true,
                              "data": {
                                "token": "550e8400-e29b-41d4-a716-446655440000",
                                "parameterName": "_csrf",
                                "headerName": "X-CSRF-TOKEN"
                              },
                              "message": "CSRF token generated successfully"
                            }
                            """),
                                            @ExampleObject(
                                                    name = "error",
                                                    summary = "CSRF token unavailable",
                                                    value =
                                                            """
                            {
                              "success": false,
                              "error": {
                                "code": "CSRF_TOKEN_UNAVAILABLE",
                                "message": "CSRF token not available",
                                "details": "Please ensure CSRF protection is enabled"
                              },
                              "timestamp": "2025-08-12T10:30:00Z"
                            }
                            """)
                                        }))
            })
    public ResponseEntity<io.vikunalabs.hmp.auth.shared.ApiResponse<Map<String, String>>> getCsrfToken(
            CsrfToken csrfToken, HttpServletRequest request) {

        log.debug("CSRF token request from IP: {}", request.getRemoteAddr());

        if (csrfToken == null) {
            log.warn("CSRF token not available for request from {}", request.getRemoteAddr());
            return ResponseEntity.ok(new io.vikunalabs.hmp.auth.shared.ApiResponse<>(
                    false,
                    null,
                    "CSRF_TOKEN_UNAVAILABLE",
                    "CSRF token not available. Please ensure CSRF protection is enabled."));
        }

        Map<String, String> tokenInfo = Map.of(
                "token", csrfToken.getToken(),
                "headerName", csrfToken.getHeaderName(),
                "parameterName", csrfToken.getParameterName());

        log.debug("Generated CSRF token for {} - header: {}", request.getRemoteAddr(), csrfToken.getHeaderName());

        return ResponseEntity.ok(new io.vikunalabs.hmp.auth.shared.ApiResponse<>(
                true, tokenInfo, null, "CSRF token generated successfully"));
    }
}
