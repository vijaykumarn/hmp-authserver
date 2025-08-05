package io.vikunalabs.hmp.auth.user.service.impl;

import io.vikunalabs.hmp.auth.user.api.dto.RegistrationRequest;
import io.vikunalabs.hmp.auth.user.domain.UserAccount;
import io.vikunalabs.hmp.auth.user.domain.UserProfile;
import io.vikunalabs.hmp.auth.user.domain.UserRole;
import io.vikunalabs.hmp.auth.user.repository.UserProfileRepository;
import io.vikunalabs.hmp.auth.user.service.UserProfileService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@RequiredArgsConstructor
@Service
public class UserProfileServiceImpl implements UserProfileService {

    private final PasswordEncoder passwordEncoder;
    private final UserProfileRepository profileRepository;

    @Override
    public UserProfile createUserProfile(RegistrationRequest registrationRequest) {
        var userProfile = buildUserProfile(registrationRequest);
        return profileRepository.save(userProfile);
    }

    @Override
    public UserProfile fetchUserProfile(Long userProfileId) {
        return profileRepository.getReferenceById(userProfileId);
    }

    private UserProfile buildUserProfile(RegistrationRequest request) {
        // build UserAccount
        UserAccount userAccount = new UserAccount();
        userAccount.setUsername(request.username());
        userAccount.setEmail(request.email());
        userAccount.setPassword(passwordEncoder.encode(request.password()));
        userAccount.setRole(UserRole.USER);

        // build UserProfile
        UserProfile userProfile = new UserProfile();
        userProfile.setConsent(request.terms());
        userProfile.setNotification(request.marketing());
        userProfile.setOrganisation(request.organisation());
        userProfile.setUserAccount(userAccount);

        // save UserProfile in UserAccount
        userAccount.setUserProfile(userProfile);

        return userProfile;
    }
}
