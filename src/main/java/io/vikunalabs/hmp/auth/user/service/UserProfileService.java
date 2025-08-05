package io.vikunalabs.hmp.auth.user.service;


import io.vikunalabs.hmp.auth.user.api.dto.RegistrationRequest;
import io.vikunalabs.hmp.auth.user.domain.UserProfile;

public interface UserProfileService {
    UserProfile createUserProfile(RegistrationRequest registrationRequest);

    UserProfile fetchUserProfile(Long userProfileId);
}
