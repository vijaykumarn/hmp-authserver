package io.vikunalabs.hmp.auth.user.api;

import io.vikunalabs.hmp.auth.shared.ApiResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RequiredArgsConstructor
@RestController
@RequestMapping("/api/auth/oauth2")
@CrossOrigin(
        origins = {"http://localhost:5173", "http://localhost:3000"},
        allowCredentials = "true",
        maxAge = 3600)
public class OAuth2Controller {

    @GetMapping("/authorization-url/google")
    public ResponseEntity<ApiResponse<Map<String, String>>> getGoogleAuthorizationUrl(HttpServletRequest request) {
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

        return ResponseEntity.ok(new ApiResponse<>(true, response));
    }
}
