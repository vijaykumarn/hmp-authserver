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
import org.springframework.http.HttpHeaders;
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
@Tag(name = "Authentication", description = "User authentication and account management endpoints")
public class AuthController {

    private final AuthService authService;
    private final AuthenticationManager authenticationManager;
    private final RateLimitingService rateLimitingService;

    @PostMapping("/register")
    @Operation(
            summary = "Register new user",
            description = "Create a new user account with email verification",
            responses = {
                @ApiResponse(
                        responseCode = "201",
                        description = "User registered successfully",
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
                                                    summary = "Successful registration",
                                                    value =
                                                            """
                            {
                              "success": true,
                              "data": {
                                "id": 12345,
                                "username": "johndoe123",
                                "email": "john.doe@example.com",
                                "firstName": null,
                                "lastName": null,
                                "organisation": "Acme Corp"
                              },
                              "message": "User registered successfully. Please check your email for verification."
                            }
                            """)
                                        })),
                @ApiResponse(
                        responseCode = "400",
                        description = "Invalid input data",
                        content =
                                @Content(
                                        mediaType = "application/json",
                                        schema =
                                                @Schema(
                                                        implementation =
                                                                io.vikunalabs.hmp.auth.shared.ApiResponse.class),
                                        examples = {
                                            @ExampleObject(
                                                    name = "validation_error",
                                                    summary = "Validation error",
                                                    value =
                                                            """
                            {
                              "success": false,
                              "error": {
                                "code": "VALIDATION_ERROR",
                                "message": "Invalid input data",
                                "details": "Password must contain at least one uppercase letter"
                              },
                              "timestamp": "2025-08-12T10:30:00Z"
                            }
                            """)
                                        })),
                @ApiResponse(
                        responseCode = "409",
                        description = "User already exists",
                        content =
                                @Content(
                                        mediaType = "application/json",
                                        schema =
                                                @Schema(
                                                        implementation =
                                                                io.vikunalabs.hmp.auth.shared.ApiResponse.class),
                                        examples = {
                                            @ExampleObject(
                                                    name = "email_exists",
                                                    summary = "Email already exists",
                                                    value =
                                                            """
                            {
                              "success": false,
                              "error": {
                                "code": "EMAIL_ALREADY_EXISTS",
                                "message": "A user with this email already exists",
                                "details": "Please use a different email address or try logging in"
                              },
                              "timestamp": "2025-08-12T10:30:00Z"
                            }
                            """)
                                        })),
                @ApiResponse(
                        responseCode = "429",
                        description = "Rate limit exceeded",
                        content =
                                @Content(
                                        mediaType = "application/json",
                                        schema =
                                                @Schema(
                                                        implementation =
                                                                io.vikunalabs.hmp.auth.shared.ApiResponse.class)))
            })
    public ResponseEntity<io.vikunalabs.hmp.auth.shared.ApiResponse<RegistrationResponse>> registerUser(
            @Valid @RequestBody RegistrationRequest request) {
        log.info("Registration attempt for email: {}", request.email());
        io.vikunalabs.hmp.auth.shared.ApiResponse<RegistrationResponse> response = authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping("/confirm-account")
    @Operation(
            summary = "Confirm account",
            description = "Verify user account using email confirmation token",
            parameters = {
                @io.swagger.v3.oas.annotations.Parameter(
                        name = "token",
                        in = ParameterIn.QUERY,
                        required = true,
                        description = "Email verification token",
                        schema = @Schema(type = "string", minLength = 1),
                        example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
            },
            responses = {
                @ApiResponse(
                        responseCode = "200",
                        description = "Account confirmed successfully",
                        headers = {
                            @io.swagger.v3.oas.annotations.headers.Header(
                                    name = HttpHeaders.SET_COOKIE,
                                    description = "Session cookie",
                                    schema =
                                            @Schema(
                                                    type = "string",
                                                    example = "SESSIONID=abc123; HttpOnly; Secure; SameSite=Strict"))
                        },
                        content =
                                @Content(
                                        mediaType = "application/json",
                                        schema =
                                                @Schema(
                                                        implementation =
                                                                io.vikunalabs.hmp.auth.shared.ApiResponse.class))),
                @ApiResponse(
                        responseCode = "400",
                        description = "Invalid or expired token",
                        content =
                                @Content(
                                        mediaType = "application/json",
                                        schema =
                                                @Schema(
                                                        implementation =
                                                                io.vikunalabs.hmp.auth.shared.ApiResponse.class)))
            })
    public ResponseEntity<io.vikunalabs.hmp.auth.shared.ApiResponse<String>> confirmAccount(
            @NotBlank @RequestParam("token") String tokenValue) {
        log.info("Account confirmation attempt with token: {}", tokenValue);

        UUID token = parseToken(tokenValue);
        io.vikunalabs.hmp.auth.shared.ApiResponse<String> response =
                authService.confirmAccount(token, TokenType.EMAIL_VERIFICATION);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/resend-verification")
    @Operation(
            summary = "Resend verification email",
            description = "Send new account verification email",
            responses = {
                @ApiResponse(
                        responseCode = "200",
                        description = "Verification email sent",
                        content =
                                @Content(
                                        mediaType = "application/json",
                                        schema =
                                                @Schema(
                                                        implementation =
                                                                io.vikunalabs.hmp.auth.shared.ApiResponse.class))),
                @ApiResponse(
                        responseCode = "429",
                        description = "Rate limit exceeded",
                        content =
                                @Content(
                                        mediaType = "application/json",
                                        schema =
                                                @Schema(
                                                        implementation =
                                                                io.vikunalabs.hmp.auth.shared.ApiResponse.class)))
            })
    public ResponseEntity<io.vikunalabs.hmp.auth.shared.ApiResponse<String>> resendVerification(
            @Valid @RequestBody ResendVerificationRequest request, HttpServletRequest httpRequest) {

        String rateLimitKey = "resend-verification:" + request.email();

        // ADDED: Rate limiting check
        if (rateLimitingService.isRateLimited(rateLimitKey, 3, Duration.ofMinutes(5))) {
            throw new TooManyRequestsException("Too many verification requests. Please try again later.");
        }

        log.info("Resend verification attempt for email: {}", request.email());
        io.vikunalabs.hmp.auth.shared.ApiResponse<String> response = authService.resendVerificationCode(request);
        return ResponseEntity.accepted().body(response);
    }

    @PostMapping("/login")
    @Operation(
            summary = "User login",
            description = "Authenticate user with username/email and password",
            responses = {
                @ApiResponse(
                        responseCode = "200",
                        description = "Login successful",
                        headers = {
                            @io.swagger.v3.oas.annotations.headers.Header(
                                    name = HttpHeaders.SET_COOKIE,
                                    description = "Session cookie",
                                    schema =
                                            @Schema(
                                                    type = "string",
                                                    example = "SESSIONID=abc123; HttpOnly; Secure; SameSite=Strict"))
                        },
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
                                                    summary = "Successful login",
                                                    value =
                                                            """
                            {
                              "success": true,
                              "data": {
                                "userId": 12345,
                                "email": "john.doe@example.com",
                                "username": "johndoe123",
                                "firstName": "John",
                                "lastName": "Doe",
                                "fullName": "John Doe",
                                "role": "USER",
                                "lastLogin": "2025-08-12T10:25:00Z",
                                "rememberMe": true
                              },
                              "message": "Login successful"
                            }
                            """)
                                        })),
                @ApiResponse(
                        responseCode = "401",
                        description = "Invalid credentials",
                        content =
                                @Content(
                                        mediaType = "application/json",
                                        schema =
                                                @Schema(
                                                        implementation =
                                                                io.vikunalabs.hmp.auth.shared.ApiResponse.class),
                                        examples = {
                                            @ExampleObject(
                                                    name = "invalid_credentials",
                                                    summary = "Invalid credentials",
                                                    value =
                                                            """
                            {
                              "success": false,
                              "error": {
                                "code": "INVALID_CREDENTIALS",
                                "message": "Invalid username or password",
                                "details": "The provided credentials do not match any user account"
                              },
                              "timestamp": "2025-08-12T10:30:00Z"
                            }
                            """)
                                        })),
                @ApiResponse(
                        responseCode = "403",
                        description = "Account locked or not verified",
                        content =
                                @Content(
                                        mediaType = "application/json",
                                        schema =
                                                @Schema(
                                                        implementation =
                                                                io.vikunalabs.hmp.auth.shared.ApiResponse.class),
                                        examples = {
                                            @ExampleObject(
                                                    name = "account_locked",
                                                    summary = "Account locked",
                                                    value =
                                                            """
                            {
                              "success": false,
                              "error": {
                                "code": "ACCOUNT_LOCKED",
                                "message": "Account temporarily locked due to multiple failed attempts",
                                "details": "Please try again in 15 minutes or reset your password"
                              },
                              "timestamp": "2025-08-12T10:30:00Z"
                            }
                            """)
                                        })),
                @ApiResponse(
                        responseCode = "429",
                        description = "Rate limit exceeded",
                        content =
                                @Content(
                                        mediaType = "application/json",
                                        schema =
                                                @Schema(
                                                        implementation =
                                                                io.vikunalabs.hmp.auth.shared.ApiResponse.class)))
            })
    public ResponseEntity<io.vikunalabs.hmp.auth.shared.ApiResponse<AuthResponse>> login(
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

            io.vikunalabs.hmp.auth.shared.ApiResponse<AuthResponse> response = authService.handleSuccessfulLogin(
                    authenticationResponse, request.rememberMe(), httpRequest, httpResponse);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            // Don't clear rate limit on failed attempts
            throw e;
        }
    }

    @PostMapping("/logout")
    @Operation(
            summary = "User logout",
            description = "Logout user and invalidate current session",
            security = @SecurityRequirement(name = "cookieAuth"),
            responses = {
                @ApiResponse(
                        responseCode = "200",
                        description = "Logout successful",
                        headers = {
                            @io.swagger.v3.oas.annotations.headers.Header(
                                    name = HttpHeaders.SET_COOKIE,
                                    description = "Expired session cookie",
                                    schema =
                                            @Schema(
                                                    type = "string",
                                                    example = "SESSIONID=; Expires=Thu, 01 Jan 1970 00:00:00 GMT"))
                        },
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
                                                    summary = "Successful logout",
                                                    value =
                                                            """
                            {
                              "success": true,
                              "data": "Logout successful",
                              "message": "User logged out successfully"
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
    public ResponseEntity<io.vikunalabs.hmp.auth.shared.ApiResponse<String>> logout(
            HttpServletRequest request, HttpServletResponse response) {
        log.info("Logout attempt");
        io.vikunalabs.hmp.auth.shared.ApiResponse<String> logoutResponse = authService.logout(request, response);
        return ResponseEntity.ok(logoutResponse);
    }

    @PostMapping("/forgot-password")
    @Operation(
            summary = "Request password reset",
            description = "Send password reset email to user",
            responses = {
                @ApiResponse(
                        responseCode = "200",
                        description = "Password reset email sent",
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
                                                    summary = "Reset email sent",
                                                    value =
                                                            """
                            {
                              "success": true,
                              "data": "Password reset email sent",
                              "message": "If an account with this email exists, a password reset link has been sent"
                            }
                            """)
                                        })),
                @ApiResponse(
                        responseCode = "429",
                        description = "Rate limit exceeded",
                        content =
                                @Content(
                                        mediaType = "application/json",
                                        schema =
                                                @Schema(
                                                        implementation =
                                                                io.vikunalabs.hmp.auth.shared.ApiResponse.class)))
            })
    public ResponseEntity<io.vikunalabs.hmp.auth.shared.ApiResponse<String>> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequest request, HttpServletRequest httpRequest) {

        String rateLimitKey = "forgot-password:" + request.email();

        // ADDED: Rate limiting check
        if (rateLimitingService.isRateLimited(rateLimitKey, 3, Duration.ofMinutes(5))) {
            throw new TooManyRequestsException("Too many password reset requests. Please try again later.");
        }

        log.info("Forgot password attempt for email: {}", request.email());
        io.vikunalabs.hmp.auth.shared.ApiResponse<String> response = authService.forgotPassword(request);
        return ResponseEntity.accepted().body(response);
    }

    @PostMapping("/reset-password")
    @Operation(
            summary = "Reset password",
            description = "Reset password using token from email",
            responses = {
                @ApiResponse(
                        responseCode = "200",
                        description = "Password reset successful",
                        content =
                                @Content(
                                        mediaType = "application/json",
                                        schema =
                                                @Schema(
                                                        implementation =
                                                                io.vikunalabs.hmp.auth.shared.ApiResponse.class))),
                @ApiResponse(
                        responseCode = "400",
                        description = "Invalid or expired token",
                        content =
                                @Content(
                                        mediaType = "application/json",
                                        schema =
                                                @Schema(
                                                        implementation =
                                                                io.vikunalabs.hmp.auth.shared.ApiResponse.class),
                                        examples = {
                                            @ExampleObject(
                                                    name = "invalid_token",
                                                    summary = "Invalid token",
                                                    value =
                                                            """
                            {
                              "success": false,
                              "error": {
                                "code": "TOKEN_INVALID",
                                "message": "Invalid or expired reset token",
                                "details": "Please request a new password reset"
                              },
                              "timestamp": "2025-08-12T10:30:00Z"
                            }
                            """)
                                        }))
            })
    public ResponseEntity<io.vikunalabs.hmp.auth.shared.ApiResponse<String>> resetPassword(
            @Valid @RequestBody ResetPasswordRequest request) {
        log.info("Password reset attempt with token");
        UUID token = parseToken(request.token());
        io.vikunalabs.hmp.auth.shared.ApiResponse<String> response =
                authService.resetPassword(token, request.newPassword());
        return ResponseEntity.ok(response);
    }

    @GetMapping("/confirm-password-token")
    @Operation(
            summary = "Validate password token",
            description = "Checks if a password reset token is valid",
            parameters = {
                @Parameter(
                        name = "token",
                        in = ParameterIn.QUERY,
                        required = true,
                        description = "Password reset token to validate",
                        schema = @Schema(type = "string", minLength = 1),
                        example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
            },
            responses = {
                @ApiResponse(
                        responseCode = "200",
                        description = "Token is valid",
                        content =
                                @Content(
                                        mediaType = "application/json",
                                        schema =
                                                @Schema(
                                                        implementation =
                                                                io.vikunalabs.hmp.auth.shared.ApiResponse.class),
                                        examples = {
                                            @ExampleObject(
                                                    name = "valid_token",
                                                    summary = "Valid token response",
                                                    value =
                                                            """
                        {
                          "success": true,
                          "data": "Token is valid",
                          "message": "Password reset token is valid"
                        }
                        """)
                                        })),
                @ApiResponse(
                        responseCode = "400",
                        description = "Invalid or expired token",
                        content =
                                @Content(
                                        mediaType = "application/json",
                                        schema =
                                                @Schema(
                                                        implementation =
                                                                io.vikunalabs.hmp.auth.shared.ApiResponse.class),
                                        examples = {
                                            @ExampleObject(
                                                    name = "invalid_token",
                                                    summary = "Invalid token response",
                                                    value =
                                                            """
                        {
                          "success": false,
                          "error": {
                            "code": "TOKEN_INVALID",
                            "message": "Invalid or expired reset token",
                            "details": "Please request a new password reset"
                          },
                          "timestamp": "2025-08-12T10:30:00Z"
                        }
                        """)
                                        }))
            })
    public ResponseEntity<io.vikunalabs.hmp.auth.shared.ApiResponse<String>> confirmPasswordToken(
            @NotBlank @RequestParam("token") String tokenValue) {
        log.info("Password token validation attempt");
        UUID token = parseToken(tokenValue);
        io.vikunalabs.hmp.auth.shared.ApiResponse<String> response = authService.confirmPasswordToken(token);
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
