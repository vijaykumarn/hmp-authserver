package io.vikunalabs.hmp.auth.user.api;

import io.vikunalabs.hmp.auth.shared.ApiResponse;
import io.vikunalabs.hmp.auth.shared.exception.InvalidTokenException;
import io.vikunalabs.hmp.auth.user.api.dto.RegistrationRequest;
import io.vikunalabs.hmp.auth.user.api.dto.RegistrationResponse;
import io.vikunalabs.hmp.auth.user.api.dto.ResendVerificationRequest;
import io.vikunalabs.hmp.auth.user.domain.TokenType;
import io.vikunalabs.hmp.auth.user.service.AuthService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@Slf4j
@RequiredArgsConstructor
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<RegistrationResponse>> registerUser(@Valid @RequestBody RegistrationRequest registrationRequest) {
        ApiResponse<RegistrationResponse> response = authService.register(registrationRequest);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping("/confirm-account")
    public ResponseEntity<ApiResponse<String>> handleTokenConfirmation(@NotBlank @RequestParam("token") String tokenValue) {
        UUID token;
        try {
            token = UUID.fromString(tokenValue);
        } catch (IllegalArgumentException ex) {
            log.warn("Invalid UUID token: {}", tokenValue);
            throw InvalidTokenException.withTokenValue(tokenValue);
        }
        ApiResponse<String> response = authService.confirmAccount(token, TokenType.EMAIL_VERIFICATION);
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

    @PostMapping("/resend-verification")
    public ResponseEntity<ApiResponse<String>> resendVerification(@Valid @RequestBody ResendVerificationRequest request) {
        ApiResponse<String> response = authService.resendVerificationCode(request);
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(response);
    }
}
