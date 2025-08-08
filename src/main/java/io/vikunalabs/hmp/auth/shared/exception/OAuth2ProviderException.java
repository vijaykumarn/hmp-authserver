package io.vikunalabs.hmp.auth.shared.exception;

// OAuth2 Provider Exception
public class OAuth2ProviderException extends AuthException {
    private OAuth2ProviderException(String message) {
        super(message);
    }

    public static OAuth2ProviderException unsupportedProvider(String provider) {
        return new OAuth2ProviderException(String.format("OAuth2 provider '%s' is not supported", provider));
    }

    public static OAuth2ProviderException providerError(String provider, String error) {
        return new OAuth2ProviderException(String.format("Error from %s: %s", provider, error));
    }
}
