package io.vikunalabs.hmp.auth.oauth2.userinfo;

import io.vikunalabs.hmp.auth.oauth2.domain.model.OAuth2UserInfo;
import io.vikunalabs.hmp.auth.oauth2.domain.principal.CustomOidcUserPrincipal;
import io.vikunalabs.hmp.auth.oauth2.service.OAuth2SecurityService;
import io.vikunalabs.hmp.auth.oauth2.service.OAuth2UserInfoFactory;
import io.vikunalabs.hmp.auth.oauth2.service.OAuth2UserProcessor;
import io.vikunalabs.hmp.auth.shared.exception.OAuth2EmailConflictException;
import io.vikunalabs.hmp.auth.shared.exception.OAuth2ProviderException;
import io.vikunalabs.hmp.auth.shared.exception.OAuth2UserDataException;
import io.vikunalabs.hmp.auth.user.domain.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

@Slf4j
@RequiredArgsConstructor
@Service
public class CustomOidcUserService extends OidcUserService {

    private final OAuth2SecurityService securityService;
    private final OAuth2UserProcessor userProcessor;

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        log.info("=== CustomOidcUserService.loadUser() CALLED ===");

        String registrationId = userRequest.getClientRegistration().getRegistrationId();

        try {
            // Step 1: Validate provider and perform initial security checks
            securityService.validateProvider(registrationId);
            securityService.performSecurityChecks(registrationId);

            // Step 2: Load user from OIDC provider (Google)
            OidcUser oidcUser = super.loadUser(userRequest);
            log.info("OIDC user loaded - subject: {}, email: {}", oidcUser.getSubject(), oidcUser.getEmail());

            // Step 3: Extract user information using our factory
            OAuth2UserInfo userInfo = OAuth2UserInfoFactory.create(registrationId, oidcUser.getAttributes());

            // Step 4: Perform email-specific security checks
            securityService.performEmailSecurityChecks(userInfo.getEmail());

            // Step 5: Process user (create or find existing)
            User user = userProcessor.processUser(userInfo, registrationId);

            // Step 6: Log success and clear rate limits
            boolean isNewUser = user.getCreatedAt().isAfter(user.getUpdatedAt().minusSeconds(5));
            securityService.logSuccessAndClearLimits(user, registrationId, isNewUser);

            // Step 7: Return custom principal that embeds our user
            CustomOidcUserPrincipal principal = new CustomOidcUserPrincipal(oidcUser, user);
            log.info("=== RETURNING CustomOidcUserPrincipal for user: {} ===", user.getEmail());
            return principal;

        } catch (OAuth2AuthenticationException e) {
            securityService.logFailure(registrationId, "unknown", e.getError().getErrorCode());
            throw e;
        } catch (OAuth2EmailConflictException | OAuth2UserDataException | OAuth2ProviderException e) {
            log.error("OIDC processing error: {}", e.getMessage(), e);
            securityService.logFailure(registrationId, "unknown", e.getClass().getSimpleName());
            throw new OAuth2AuthenticationException(new OAuth2Error("user_processing_error", e.getMessage(), null));
        } catch (Exception e) {
            log.error("Unexpected error processing OIDC user", e);
            securityService.logFailure(registrationId, "unknown", "internal_error");
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("internal_error", "An unexpected error occurred during sign-in", null));
        }
    }
}
