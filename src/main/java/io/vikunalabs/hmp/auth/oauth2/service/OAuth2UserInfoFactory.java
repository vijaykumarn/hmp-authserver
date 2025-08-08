package io.vikunalabs.hmp.auth.oauth2.service;

import io.vikunalabs.hmp.auth.oauth2.domain.model.GitHubOAuth2UserInfo;
import io.vikunalabs.hmp.auth.oauth2.domain.model.GoogleOAuth2UserInfo;
import io.vikunalabs.hmp.auth.oauth2.domain.model.OAuth2UserInfo;
import io.vikunalabs.hmp.auth.shared.exception.OAuth2ProviderException;
import java.util.Map;
import org.springframework.stereotype.Component;

@Component
public class OAuth2UserInfoFactory {

    public static OAuth2UserInfo create(String registrationId, Map<String, Object> attributes) {
        return switch (registrationId.toLowerCase()) {
            case "google" -> new GoogleOAuth2UserInfo(attributes);
            case "github" -> new GitHubOAuth2UserInfo(attributes);
            // Add more providers as needed
            default -> throw OAuth2ProviderException.unsupportedProvider(registrationId);
        };
    }
}
