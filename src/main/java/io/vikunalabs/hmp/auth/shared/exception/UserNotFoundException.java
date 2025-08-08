package io.vikunalabs.hmp.auth.shared.exception;

public class UserNotFoundException extends AuthException {

    private UserNotFoundException(String message) {
        super(message);
    }

    public static UserNotFoundException withID(Long id) {
        return new UserNotFoundException("User profile with id " + id + " not found");
    }

    public static UserNotFoundException withUsername(String usernameOrEmail) {
        return new UserNotFoundException("User profile with username or email: " + usernameOrEmail + " not found");
    }

    public static UserNotFoundException withUsernameAndEmail(String username, String email) {
        return new UserNotFoundException(
                "User profile with username or email: " + (username.isBlank() ? email : username) + " not found");
    }
}
