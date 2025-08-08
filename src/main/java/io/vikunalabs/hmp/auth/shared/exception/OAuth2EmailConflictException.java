package io.vikunalabs.hmp.auth.shared.exception;

public class OAuth2EmailConflictException extends AuthException {
    private OAuth2EmailConflictException(String message) {
        super(message);
    }

    public static OAuth2EmailConflictException withEmail(String email, String existingProvider) {
        return new OAuth2EmailConflictException(String.format(
                "Email %s is already registered with %s. Please use %s to sign in or contact support to link accounts.",
                email, existingProvider, existingProvider));
    }
}
