package io.vikunalabs.hmp.auth.shared.exception;

public class OAuth2UserDataException extends AuthException {
    private OAuth2UserDataException(String message) {
        super(message);
    }

    public static OAuth2UserDataException missingRequiredData(String field) {
        return new OAuth2UserDataException(String.format("Required field '%s' is missing from OAuth2 provider", field));
    }

    public static OAuth2UserDataException invalidEmailFormat(String email) {
        return new OAuth2UserDataException(
                String.format("Invalid email format received from OAuth2 provider: %s", email));
    }
}
