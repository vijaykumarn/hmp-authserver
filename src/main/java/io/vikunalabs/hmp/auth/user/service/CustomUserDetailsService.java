package io.vikunalabs.hmp.auth.user.service;

import io.vikunalabs.hmp.auth.user.domain.UserAccount;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserAccountService accountService;

    @Override
    public UserDetails loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {
        UserAccount userAccount = accountService.getByUsernameOrEmail(usernameOrEmail, usernameOrEmail);
        return new CustomUserDetails(userAccount);
    }
}