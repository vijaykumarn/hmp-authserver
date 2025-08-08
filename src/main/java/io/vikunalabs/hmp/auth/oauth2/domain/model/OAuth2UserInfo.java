package io.vikunalabs.hmp.auth.oauth2.domain.model;

import io.vikunalabs.hmp.auth.shared.exception.OAuth2UserDataException;
import java.util.Map;
import org.springframework.util.StringUtils;

// Base abstract class for OAuth2 user information
public abstract class OAuth2UserInfo {
    protected Map<String, Object> attributes;

    public OAuth2UserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    public abstract String getId();

    public abstract String getEmail();

    public abstract String getFirstName();

    public abstract String getLastName();

    public abstract String getImageUrl();

    protected String getAttributeAsString(String key) {
        Object value = attributes.get(key);
        return value != null ? value.toString() : null;
    }

    public void validateRequiredFields() {
        if (!StringUtils.hasText(getId())) {
            throw OAuth2UserDataException.missingRequiredData("User ID");
        }
        if (!StringUtils.hasText(getEmail())) {
            throw OAuth2UserDataException.missingRequiredData("Email");
        }
        if (!isValidEmail(getEmail())) {
            throw OAuth2UserDataException.invalidEmailFormat(getEmail());
        }
    }

    private boolean isValidEmail(String email) {
        return StringUtils.hasText(email)
                && email.contains("@")
                && email.matches("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");
    }
}
