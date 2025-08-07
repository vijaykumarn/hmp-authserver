package io.vikunalabs.hmp.auth.user.api;

import io.vikunalabs.hmp.auth.shared.ApiResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

import io.vikunalabs.hmp.auth.shared.ApiResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@CrossOrigin(
        origins = {"http://localhost:5173", "http://localhost:3000"},
        allowCredentials = "true",
        maxAge = 3600
)
public class CsrfController {

    @GetMapping("/csrf-token")
    public ResponseEntity<ApiResponse<Map<String, String>>> getCsrfToken(CsrfToken csrfToken) {
        if (csrfToken == null) {
            log.warn("CSRF token not available");
            ApiResponse<Map<String, String>> errorResponse = new ApiResponse<>(
                    false,
                    null,
                    "CSRF_TOKEN_UNAVAILABLE",
                    "CSRF token not available"
            );
            return ResponseEntity.ok(errorResponse);
        }

        Map<String, String> tokenInfo = Map.of(
                "token", csrfToken.getToken(),
                "headerName", csrfToken.getHeaderName(),
                "parameterName", csrfToken.getParameterName()
        );

        ApiResponse<Map<String, String>> response = new ApiResponse<>(true, tokenInfo);
        return ResponseEntity.ok(response);
    }
}