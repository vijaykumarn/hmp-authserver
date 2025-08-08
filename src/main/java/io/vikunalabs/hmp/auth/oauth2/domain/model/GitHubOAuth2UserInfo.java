package io.vikunalabs.hmp.auth.oauth2.domain.model;

import java.util.Map;

// GitHub implementation (for future use)
public class GitHubOAuth2UserInfo extends OAuth2UserInfo {
    public GitHubOAuth2UserInfo(Map<String, Object> attributes) {
        super(attributes);
    }

    @Override
    public String getId() {
        return getAttributeAsString("id");
    }

    @Override
    public String getEmail() {
        return getAttributeAsString("email");
    }

    @Override
    public String getFirstName() {
        String name = getAttributeAsString("name");
        return name != null ? name.split(" ")[0] : null;
    }

    @Override
    public String getLastName() {
        String name = getAttributeAsString("name");
        if (name != null) {
            String[] parts = name.split(" ");
            return parts.length > 1 ? parts[parts.length - 1] : null;
        }
        return null;
    }

    @Override
    public String getImageUrl() {
        return getAttributeAsString("avatar_url");
    }
}
