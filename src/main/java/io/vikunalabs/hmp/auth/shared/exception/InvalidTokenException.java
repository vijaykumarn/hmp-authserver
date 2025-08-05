package io.vikunalabs.hmp.auth.shared.exception;

public class InvalidTokenException extends AuthException {
    private InvalidTokenException(String message) {
        super(message);
    }

    public static InvalidTokenException withTokenValue(String tokenValue) {
        return new InvalidTokenException("TokenValue: " + tokenValue + " is invalid");
    }
}
