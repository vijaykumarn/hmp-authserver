package io.vikunalabs.hmp.auth.user.service;

import io.vikunalabs.hmp.auth.user.domain.UserAccount;
import io.vikunalabs.hmp.auth.user.domain.UserRole;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

public class CustomUserDetails implements UserDetails {

    private final Long userId;
    private final String username;
    private final String password;
    private final UserRole role;
    private final boolean accountEnabled;
    private final boolean credentialsExpired;
    private final boolean accountExpired;
    private final boolean accountLocked;

    CustomUserDetails(UserAccount userAccount) {
        this.userId = userAccount.getId();
        this.username = userAccount.getUsername();
        this.password = userAccount.getPassword();
        this.role = userAccount.getRole();
        this.accountEnabled = userAccount.isAccountEnabled();
        this.credentialsExpired = userAccount.isCredentialsExpired();
        this.accountExpired = userAccount.isAccountExpired();
        this.accountLocked = userAccount.isAccountLocked();
    }

    public Long getUserId() {
        return this.userId;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.name()));
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return !this.accountExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return !this.accountLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return !this.credentialsExpired;
    }

    @Override
    public boolean isEnabled() {
        return this.accountEnabled;
    }
}