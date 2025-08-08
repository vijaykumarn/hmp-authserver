package io.vikunalabs.hmp.auth.oauth2.domain.principal;

import io.vikunalabs.hmp.auth.user.domain.User;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.oidc.AddressStandardClaim;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

// Custom OIDC principal that implements OidcUser but contains our User entity
public class CustomOidcUserPrincipal implements OidcUser {
    private final OidcUser delegate;
    private final User user;

    public CustomOidcUserPrincipal(OidcUser delegate, User user) {
        this.delegate = delegate;
        this.user = user;
    }

    public User getUser() {
        return user;
    }

    // Delegate all OidcUser methods to the original
    @Override
    public Map<String, Object> getAttributes() {
        return delegate.getAttributes();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // Use our user's authorities instead of the default ones
        return List.of(new SimpleGrantedAuthority("ROLE_" + user.getRole().name()));
    }

    @Override
    public String getName() {
        return user.getEmail();
    }

    @Override
    public OidcIdToken getIdToken() {
        return delegate.getIdToken();
    }

    @Override
    public Map<String, Object> getClaims() {
        return Map.of();
    }

    @Override
    public OidcUserInfo getUserInfo() {
        return delegate.getUserInfo();
    }

    // Implement the rest of the OidcUser interface by delegating
    @Override
    public String getSubject() {
        return delegate.getSubject();
    }

    @Override
    public String getFullName() {
        return delegate.getFullName();
    }

    @Override
    public String getGivenName() {
        return delegate.getGivenName();
    }

    @Override
    public String getFamilyName() {
        return delegate.getFamilyName();
    }

    @Override
    public String getMiddleName() {
        return delegate.getMiddleName();
    }

    @Override
    public String getPreferredUsername() {
        return delegate.getPreferredUsername();
    }

    @Override
    public String getProfile() {
        return delegate.getProfile();
    }

    @Override
    public String getPicture() {
        return delegate.getPicture();
    }

    @Override
    public String getWebsite() {
        return delegate.getWebsite();
    }

    @Override
    public String getEmail() {
        return delegate.getEmail();
    }

    @Override
    public Boolean getEmailVerified() {
        return delegate.getEmailVerified();
    }

    @Override
    public String getGender() {
        return delegate.getGender();
    }

    @Override
    public String getBirthdate() {
        return delegate.getBirthdate();
    }

    @Override
    public String getLocale() {
        return delegate.getLocale();
    }

    @Override
    public String getPhoneNumber() {
        return delegate.getPhoneNumber();
    }

    @Override
    public Boolean getPhoneNumberVerified() {
        return delegate.getPhoneNumberVerified();
    }

    @Override
    public AddressStandardClaim getAddress() {
        return OidcUser.super.getAddress();
    }

    @Override
    public String getNickName() {
        return OidcUser.super.getNickName();
    }

    @Override
    public String getZoneInfo() {
        return OidcUser.super.getZoneInfo();
    }

    @Override
    public Instant getUpdatedAt() {
        return delegate.getUpdatedAt();
    }
}
