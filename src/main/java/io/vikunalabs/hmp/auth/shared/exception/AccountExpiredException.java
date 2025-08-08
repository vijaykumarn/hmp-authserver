package io.vikunalabs.hmp.auth.shared.exception;

public class AccountExpiredException extends RuntimeException {
    public AccountExpiredException(String message) {
        super(message);
    }
}
