package io.vikunalabs.hmp.auth.user.api;

import io.vikunalabs.hmp.auth.shared.ApiResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Slf4j
@RequiredArgsConstructor
@RestController
@RequestMapping("/api/auth/oauth2")
@CrossOrigin(
        origins = {"http://localhost:5173", "http://localhost:3000"},
        allowCredentials = "true",
        maxAge = 3600
)
public class OAuth2Controller {

    @GetMapping("/authorization-url/google")
    public ResponseEntity<ApiResponse<Map<String, String>>> getGoogleAuthorizationUrl() {
        log.info("Generating Google OAuth2 authorization URL");
        
        String authorizationUrl = "/oauth2/authorization/google";
        
        Map<String, String> response = Map.of(
                "authorizationUrl", authorizationUrl,
                "provider", "google"
        );
        
        return ResponseEntity.ok(new ApiResponse<>(true, response));
    }
}