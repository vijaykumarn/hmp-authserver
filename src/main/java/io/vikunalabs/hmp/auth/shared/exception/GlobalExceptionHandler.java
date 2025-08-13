package io.vikunalabs.hmp.auth.shared.exception;

import io.vikunalabs.hmp.auth.shared.ApiResponse;
import java.util.HashMap;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(DisabledException.class)
    public ResponseEntity<ApiResponse<Void>> handleDisabledException(DisabledException ex) {
        log.warn("Login attempt with disabled account: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(new ApiResponse<>(
                        false, null, "ACCOUNT_DISABLED", "Account is disabled. Please verify your email address."));
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiResponse<Void>> handleBadCredentials(BadCredentialsException ex) {
        log.warn("Invalid login credentials: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new ApiResponse<>(false, null, "INVALID_CREDENTIALS", "Invalid username or password"));
    }

    @ExceptionHandler({EmailAlreadyTakenException.class, UsernameAlreadyTakenException.class})
    public ResponseEntity<ApiResponse<Void>> handleConflict(RuntimeException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(new ApiResponse<>(false, null, "CONFLICT", ex.getMessage()));
    }

    @ExceptionHandler({InvalidTokenException.class, TokenExpiredException.class, TokenNotFoundException.class})
    public ResponseEntity<ApiResponse<Void>> handleBadRequest(RuntimeException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ApiResponse<>(false, null, "INVALID_TOKEN", ex.getMessage()));
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<ApiResponse<Void>> handleNotFound(RuntimeException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(new ApiResponse<>(false, null, "USER_NOT_FOUND", ex.getMessage()));
    }

    @ExceptionHandler(TooManyRequestsException.class)
    public ResponseEntity<ApiResponse<Void>> handleTooManyRequests(RuntimeException ex) {
        log.warn("Rate limit exceeded: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .body(new ApiResponse<>(false, null, "RATE_LIMIT_EXCEEDED", ex.getMessage()));
    }

    @ExceptionHandler({
        InvalidCredentialsException.class,
        AccountDisabledException.class,
        AccountLockedException.class,
        AccountExpiredException.class,
        AccountAlreadyActivatedException.class
    })
    public ResponseEntity<ApiResponse<Void>> handleUnauthorized(RuntimeException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new ApiResponse<>(false, null, "UNAUTHORIZED", ex.getMessage()));
    }

    @ExceptionHandler(LockedException.class)
    public ResponseEntity<ApiResponse<Void>> handleLockedException(LockedException ex) {
        log.warn("Account locked: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.LOCKED)
                .body(new ApiResponse<>(
                        false, null, "ACCOUNT_LOCKED", "Account temporarily locked due to multiple failed attempts"));
    }

    @ExceptionHandler(AccountStatusException.class)
    public ResponseEntity<ApiResponse<Void>> handleAccountStatusException(AccountStatusException ex) {
        log.warn("Account status exception: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(new ApiResponse<>(
                        false, null, "ACCOUNT_STATUS_ERROR", "Account access denied due to account status"));
    }

    @ExceptionHandler({OAuth2EmailConflictException.class, OAuth2ProviderException.class, OAuth2UserDataException.class
    })
    public ResponseEntity<ApiResponse<Void>> handleOAuth2Exceptions(RuntimeException ex) {
        log.warn("OAuth2 error: {}", ex.getMessage());
        String errorCode = determineOAuth2ErrorCode(ex);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ApiResponse<>(false, null, errorCode, ex.getMessage()));
    }

    @ExceptionHandler(OAuth2AuthenticationException.class)
    public ResponseEntity<ApiResponse<Void>> handleOAuth2AuthenticationException(OAuth2AuthenticationException ex) {
        log.warn(
                "OAuth2 authentication failed: {} - {}",
                ex.getError().getErrorCode(),
                ex.getError().getDescription());
        String userFriendlyMessage = getUserFriendlyOAuth2Message(ex);
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new ApiResponse<>(
                        false, null, "OAUTH2_" + ex.getError().getErrorCode().toUpperCase(), userFriendlyMessage));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<Map<String, String>>> handleValidationExceptions(
            MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach(error -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });

        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ApiResponse<>(false, errors, "VALIDATION_ERROR", "Request validation failed"));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Object>> handleGenericException(Exception ex) {
        log.error("Unexpected error occurred", ex);
        ApiResponse<Object> response = new ApiResponse<>(
                false,
                null, // no data
                "INTERNAL_SERVER_ERROR", // error code
                "An unexpected error occurred" // message
                );
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }

    private String determineOAuth2ErrorCode(RuntimeException ex) {
        if (ex instanceof OAuth2EmailConflictException) return "OAUTH2_EMAIL_CONFLICT";
        if (ex instanceof OAuth2ProviderException) return "OAUTH2_PROVIDER_ERROR";
        if (ex instanceof OAuth2UserDataException) return "OAUTH2_USER_DATA_ERROR";
        return "OAUTH2_ERROR";
    }

    private String getUserFriendlyOAuth2Message(OAuth2AuthenticationException ex) {
        return switch (ex.getError().getErrorCode()) {
            case "access_denied" -> "You cancelled the sign-in process";
            case "invalid_request" -> "Invalid authentication request";
            case "server_error" -> "Provider service unavailable";
            case "temporarily_unavailable" -> "Service temporarily unavailable";
            case "invalid_scope" -> "Invalid permissions requested";
            default -> "Authentication failed";
        };
    }
}
