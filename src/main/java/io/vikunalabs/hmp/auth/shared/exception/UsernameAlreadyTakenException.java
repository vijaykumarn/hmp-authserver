package io.vikunalabs.hmp.auth.shared.exception;

public class UsernameAlreadyTakenException extends AuthException {
    private UsernameAlreadyTakenException(String message) {
        super(message);
    }

    public static UsernameAlreadyTakenException withUsername(String username) {
        return new UsernameAlreadyTakenException(String.format("Username: %s is already taken!", username));
    }
}
