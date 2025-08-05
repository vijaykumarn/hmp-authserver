package io.vikunalabs.hmp.auth.shared.exception;

public class TokenExpiredException extends AuthException {
    private TokenExpiredException(String message) {
        super(message);
    }

    public static TokenExpiredException withToken(String tokenValue) {
        return new TokenExpiredException("Token expired. Token: " + tokenValue);
    }
}
