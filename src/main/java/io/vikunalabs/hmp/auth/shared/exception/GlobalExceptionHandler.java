package io.vikunalabs.hmp.auth.shared.exception;

import io.vikunalabs.hmp.auth.shared.ApiResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler({
            EmailAlreadyTakenException.class,
            UsernameAlreadyTakenException.class
    })
    public ResponseEntity<ApiResponse<Object>> handleConflict(RuntimeException ex) {
        ApiResponse<Object> response = new ApiResponse<>(false, "CONFLICT", ex.getMessage());
        return ResponseEntity.status(HttpStatus.CONFLICT).body(response);
    }

    @ExceptionHandler({
            InvalidTokenException.class,
            TokenExpiredException.class,
            TokenNotFoundException.class
    })
    public ResponseEntity<ApiResponse<Object>> handleBadRequest(RuntimeException ex) {
        ApiResponse<Object> response = new ApiResponse<>(false, "BAD_REQUEST", ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }

    @ExceptionHandler({
            UserNotFoundException.class
    })
    public ResponseEntity<ApiResponse<Object>> handleNotFound(RuntimeException ex) {
        ApiResponse<Object> response = new ApiResponse<>(false, "NOT_FOUND", ex.getMessage());
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
    }

    @ExceptionHandler({
            TooManyRequestsException.class
    })
    public ResponseEntity<ApiResponse<Object>> handleTooManyRequests(RuntimeException ex) {
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

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<Map<String, String>>> handleValidationExceptions(
            MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach((error) -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });

        ApiResponse<Map<String, String>> response = new ApiResponse<>(false, errors,
                "VALIDATION_ERROR", "Validation failed");
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Object>> handleGenericException(Exception ex) {
        log.error("Unexpected error occurred", ex);
        ApiResponse<Object> response = new ApiResponse<>(false, "INTERNAL_SERVER_ERROR",
                "An unexpected error occurred");
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }
}
