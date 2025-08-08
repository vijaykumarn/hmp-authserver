package io.vikunalabs.hmp.auth.user.api;

import io.vikunalabs.hmp.auth.shared.ApiResponse;
import io.vikunalabs.hmp.auth.shared.exception.InvalidTokenException;
import io.vikunalabs.hmp.auth.shared.exception.TooManyRequestsException;
import io.vikunalabs.hmp.auth.shared.security.RateLimitingService;
import io.vikunalabs.hmp.auth.user.api.dto.*;
import io.vikunalabs.hmp.auth.user.domain.TokenType;
import io.vikunalabs.hmp.auth.user.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import java.time.Duration;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RequiredArgsConstructor
@RestController
@RequestMapping("/api/auth")
@CrossOrigin(
        origins = {"http://localhost:5173", "http://localhost:3000"},
        allowCredentials = "true",
        maxAge = 3600)
public class AuthController {

    private final AuthService authService;
    private final AuthenticationManager authenticationManager;
    private final RateLimitingService rateLimitingService;

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<RegistrationResponse>> registerUser(
            @Valid @RequestBody RegistrationRequest request) {
        log.info("Registration attempt for email: {}", request.email());
        ApiResponse<RegistrationResponse> response = authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping("/confirm-account")
    public ResponseEntity<ApiResponse<String>> confirmAccount(@NotBlank @RequestParam("token") String tokenValue) {
        log.info("Account confirmation attempt with token: {}", tokenValue);

        UUID token = parseToken(tokenValue);
        ApiResponse<String> response = authService.confirmAccount(token, TokenType.EMAIL_VERIFICATION);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/resend-verification")
    public ResponseEntity<ApiResponse<String>> resendVerification(
            @Valid @RequestBody ResendVerificationRequest request, HttpServletRequest httpRequest) {

        String rateLimitKey = "resend-verification:" + request.email();

        // ADDED: Rate limiting check
        if (rateLimitingService.isRateLimited(rateLimitKey, 3, Duration.ofMinutes(5))) {
            throw new TooManyRequestsException("Too many verification requests. Please try again later.");
        }

        log.info("Resend verification attempt for email: {}", request.email());
        ApiResponse<String> response = authService.resendVerificationCode(request);
        return ResponseEntity.accepted().body(response);
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<AuthResponse>> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {

        String clientIp = getClientIP(httpRequest);
        String rateLimitKey = "login:" + clientIp;

        // ADDED: Rate limiting check
        if (rateLimitingService.isRateLimited(rateLimitKey, 5, Duration.ofMinutes(15))) {
            throw new TooManyRequestsException("Too many login attempts. Please try again later.");
        }

        log.info("Login attempt for email: {}", request.login());

        try {
            Authentication authenticationRequest =
                    UsernamePasswordAuthenticationToken.unauthenticated(request.login(), request.password());

            Authentication authenticationResponse = authenticationManager.authenticate(authenticationRequest);

            // ADDED: Clear rate limit on successful login
            rateLimitingService.clearRateLimit(rateLimitKey);

            ApiResponse<AuthResponse> response = authService.handleSuccessfulLogin(
                    authenticationResponse, request.rememberMe(), httpRequest, httpResponse);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            // Don't clear rate limit on failed attempts
            throw e;
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<String>> logout(HttpServletRequest request, HttpServletResponse response) {
        log.info("Logout attempt");
        ApiResponse<String> logoutResponse = authService.logout(request, response);
        return ResponseEntity.ok(logoutResponse);
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<ApiResponse<String>> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequest request, HttpServletRequest httpRequest) {

        String rateLimitKey = "forgot-password:" + request.email();

        // ADDED: Rate limiting check
        if (rateLimitingService.isRateLimited(rateLimitKey, 3, Duration.ofMinutes(5))) {
            throw new TooManyRequestsException("Too many password reset requests. Please try again later.");
        }

        log.info("Forgot password attempt for email: {}", request.email());
        ApiResponse<String> response = authService.forgotPassword(request);
        return ResponseEntity.accepted().body(response);
    }

    @PostMapping("/reset-password")
    public ResponseEntity<ApiResponse<String>> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        log.info("Password reset attempt with token");
        UUID token = parseToken(request.token());
        ApiResponse<String> response = authService.resetPassword(token, request.newPassword());
        return ResponseEntity.ok(response);
    }

    @GetMapping("/confirm-password-token")
    public ResponseEntity<ApiResponse<String>> confirmPasswordToken(
            @NotBlank @RequestParam("token") String tokenValue) {
        log.info("Password token validation attempt");
        UUID token = parseToken(tokenValue);
        ApiResponse<String> response = authService.confirmPasswordToken(token);
        return ResponseEntity.ok(response);
    }

    private String getClientIP(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (StringUtils.hasText(xForwardedFor)) {
            return xForwardedFor.split(",")[0].trim();
        }
        String xRealIp = request.getHeader("X-Real-IP");
        if (StringUtils.hasText(xRealIp)) {
            return xRealIp;
        }
        return request.getRemoteAddr();
    }

    private UUID parseToken(String tokenValue) {
        try {
            return UUID.fromString(tokenValue);
        } catch (IllegalArgumentException ex) {
            log.warn("Invalid UUID token format: {}", tokenValue);
            throw InvalidTokenException.withTokenValue(tokenValue);
        }
    }
}
