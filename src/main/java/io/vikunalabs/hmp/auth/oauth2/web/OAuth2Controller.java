package io.vikunalabs.hmp.auth.oauth2.web;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RequiredArgsConstructor
@RestController
@RequestMapping("/api/auth/oauth2")
@Tag(name = "OAuth2", description = "OAuth2 authentication endpoints")
public class OAuth2Controller {

    @GetMapping("/authorization-url/google")
    @Operation(
            summary = "Get Google OAuth2 authorization URL",
            description = "Get authorization URL for Google OAuth2 login",
            responses = {
                @ApiResponse(
                        responseCode = "200",
                        description = "Authorization URL generated",
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
                                                    summary = "Google auth URL",
                                                    value =
                                                            """
                                                            {
                                                              "success": true,
                                                              "data": {
                                                                "authorizationUrl": "https://accounts.google.com/oauth/authorize?client_id=...",
                                                                "state": "random_state_string"
                                                              }
                                                            }
                                                            """)
                                        })),
                @ApiResponse(
                        responseCode = "500",
                        description = "Internal server error",
                        content =
                                @Content(
                                        mediaType = "application/json",
                                        schema =
                                                @Schema(
                                                        implementation =
                                                                io.vikunalabs.hmp.auth.shared.ApiResponse.class)))
            })
    public ResponseEntity<io.vikunalabs.hmp.auth.shared.ApiResponse<Map<String, String>>> getGoogleAuthorizationUrl(
            HttpServletRequest request) {
        log.info("Generating Google OAuth2 authorization URL");

        // Build the full authorization URL
        String baseUrl = request.getRequestURL().toString().replace(request.getRequestURI(), "");
        String authorizationUrl = baseUrl + "/oauth2/authorization/google";

        Map<String, String> response = Map.of(
                "authorizationUrl",
                authorizationUrl,
                "provider",
                "google",
                "state",
                UUID.randomUUID().toString());

        return ResponseEntity.ok(new io.vikunalabs.hmp.auth.shared.ApiResponse<>(true, response));
    }
}
