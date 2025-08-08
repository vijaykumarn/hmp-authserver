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

        ApiResponse<Void> response = new ApiResponse<>(
                false, null, "ACCOUNT_NOT_VERIFIED", "Please verify your email address before logging in");

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiResponse<Void>> handleBadCredentials(BadCredentialsException ex) {
        log.warn("Invalid login credentials: {}", ex.getMessage());

        ApiResponse<Void> response =
                new ApiResponse<>(false, null, "INVALID_CREDENTIALS", "Invalid username or password");

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    @ExceptionHandler({EmailAlreadyTakenException.class, UsernameAlreadyTakenException.class})
    public ResponseEntity<ApiResponse<Object>> handleConflict(RuntimeException ex) {
        ApiResponse<Object> response = new ApiResponse<>(false, "CONFLICT", ex.getMessage());
        return ResponseEntity.status(HttpStatus.CONFLICT).body(response);
    }

    @ExceptionHandler({InvalidTokenException.class, TokenExpiredException.class, TokenNotFoundException.class})
    public ResponseEntity<ApiResponse<Object>> handleBadRequest(RuntimeException ex) {
        ApiResponse<Object> response = new ApiResponse<>(false, "BAD_REQUEST", ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }

    @ExceptionHandler({UserNotFoundException.class})
    public ResponseEntity<ApiResponse<Object>> handleNotFound(RuntimeException ex) {
        ApiResponse<Object> response = new ApiResponse<>(false, "NOT_FOUND", ex.getMessage());
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
    }

    @ExceptionHandler({TooManyRequestsException.class})
    public ResponseEntity<ApiResponse<Object>> handleTooManyRequests(RuntimeException ex) {
        log.warn("Rate limit exceeded: {}", ex.getMessage());
        ApiResponse<Object> response = new ApiResponse<>(false, "TOO_MANY_REQUESTS", ex.getMessage());
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(response);
    }

    @ExceptionHandler({
        InvalidCredentialsException.class,
        AccountDisabledException.class,
        AccountLockedException.class,
        AccountExpiredException.class,
        AccountAlreadyActivatedException.class
    })
    public ResponseEntity<ApiResponse<Object>> handleUnauthorized(RuntimeException ex) {
        ApiResponse<Object> response = new ApiResponse<>(false, "UNAUTHORIZED", ex.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    @ExceptionHandler(LockedException.class)
    public ResponseEntity<ApiResponse<Void>> handleLockedException(LockedException ex) {
        log.warn("Account locked: {}", ex.getMessage());

        ApiResponse<Void> response = new ApiResponse<>(
                false, null, "ACCOUNT_LOCKED", "Account is temporarily locked due to too many failed login attempts");

        return ResponseEntity.status(HttpStatus.LOCKED).body(response);
    }

    @ExceptionHandler(AccountStatusException.class)
    public ResponseEntity<ApiResponse<Void>> handleAccountStatusException(AccountStatusException ex) {
        log.warn("Account status exception: {}", ex.getMessage());

        ApiResponse<Void> response =
                new ApiResponse<>(false, null, "ACCOUNT_STATUS_ERROR", "Account access denied due to account status");

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
    }

    @ExceptionHandler({OAuth2EmailConflictException.class, OAuth2ProviderException.class, OAuth2UserDataException.class
    })
    public ResponseEntity<ApiResponse<Object>> handleOAuth2Exceptions(RuntimeException ex) {
        log.warn("OAuth2 error: {}", ex.getMessage());

        String errorCode = determineOAuth2ErrorCode(ex);
        ApiResponse<Object> response = new ApiResponse<>(false, errorCode, ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }

    @ExceptionHandler(OAuth2AuthenticationException.class)
    public ResponseEntity<ApiResponse<Object>> handleOAuth2AuthenticationException(OAuth2AuthenticationException ex) {
        log.warn(
                "OAuth2 authentication failed: {} - {}",
                ex.getError().getErrorCode(),
                ex.getError().getDescription());

        String userFriendlyMessage = getUserFriendlyOAuth2Message(ex);

        ApiResponse<Object> response = new ApiResponse<>(
                false, "OAUTH2_" + ex.getError().getErrorCode().toUpperCase(), userFriendlyMessage);

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    private String determineOAuth2ErrorCode(RuntimeException ex) {
        if (ex instanceof OAuth2EmailConflictException) {
            return "OAUTH2_EMAIL_CONFLICT";
        } else if (ex instanceof OAuth2ProviderException) {
            return "OAUTH2_PROVIDER_ERROR";
        } else if (ex instanceof OAuth2UserDataException) {
            return "OAUTH2_USER_DATA_ERROR";
        }
        return "OAUTH2_ERROR";
    }

    private String getUserFriendlyOAuth2Message(OAuth2AuthenticationException ex) {
        String errorCode = ex.getError().getErrorCode();

        return switch (errorCode) {
            case "access_denied" -> "You cancelled the sign-in process. Please try again if you want to continue.";
            case "invalid_request" -> "There was an issue with the sign-in request. Please try again.";
            case "server_error" -> "Google's servers are experiencing issues. Please try again in a few minutes.";
            case "temporarily_unavailable" ->
                "Google's sign-in service is temporarily unavailable. Please try again later.";
            case "invalid_scope" -> "The requested permissions are not available. Please contact support.";
            default -> "Sign-in with Google failed. Please try again or use email/password login.";
        };
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<Map<String, String>>> handleValidationExceptions(
            MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach((error) -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });

        ApiResponse<Map<String, String>> response =
                new ApiResponse<>(false, errors, "VALIDATION_ERROR", "Validation failed");
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Object>> handleGenericException(Exception ex) {
        log.error("Unexpected error occurred", ex);
        ApiResponse<Object> response =
                new ApiResponse<>(false, "INTERNAL_SERVER_ERROR", "An unexpected error occurred");
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }
}
