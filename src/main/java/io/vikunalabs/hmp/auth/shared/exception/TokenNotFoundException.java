package io.vikunalabs.hmp.auth.shared.exception;

public class TokenNotFoundException extends AuthException {
    private TokenNotFoundException(String message) {
        super(message);
    }

    public static TokenNotFoundException withToken(String token) {
        return new TokenNotFoundException("Token not found: " + token);
    }
}