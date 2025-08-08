package io.vikunalabs.hmp.auth.oauth2.domain.model;

import java.util.Map;

// Google-specific implementation
public class GoogleOAuth2UserInfo extends OAuth2UserInfo {
    public GoogleOAuth2UserInfo(Map<String, Object> attributes) {
        super(attributes);
    }

    @Override
    public String getId() {
        return getAttributeAsString("sub");
    }

    @Override
    public String getEmail() {
        return getAttributeAsString("email");
    }

    @Override
    public String getFirstName() {
        return getAttributeAsString("given_name");
    }

    @Override
    public String getLastName() {
        return getAttributeAsString("family_name");
    }

    @Override
    public String getImageUrl() {
        return getAttributeAsString("picture");
    }
}
