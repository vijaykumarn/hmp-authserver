package io.vikunalabs.hmp.auth.shared.exception;

public class AccountAlreadyActivatedException extends AuthException {
    private AccountAlreadyActivatedException(String message) {
        super(message);
    }

    public static AccountAlreadyActivatedException withId(String id) {
        return new AccountAlreadyActivatedException(String.format("Account with Id %s already activated", id));
    }

    public static AccountAlreadyActivatedException withEmail(String email) {
        return new AccountAlreadyActivatedException(String.format("Account with email %s already activated", email));
    }
}
