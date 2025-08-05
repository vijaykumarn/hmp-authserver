package io.vikunalabs.hmp.auth.shared.exception;

public class EmailAlreadyTakenException extends AuthException {
    private EmailAlreadyTakenException(String message) {
        super(message);
    }

    public static EmailAlreadyTakenException withEmail(String email) {
        return new EmailAlreadyTakenException(String.format("Email: %s is already taken!", email));
    }
}
