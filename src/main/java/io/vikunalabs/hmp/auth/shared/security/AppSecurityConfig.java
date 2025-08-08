package io.vikunalabs.hmp.auth.shared.security;

import io.vikunalabs.hmp.auth.oauth2.handler.OAuth2AuthenticationFailureHandler;
import io.vikunalabs.hmp.auth.oauth2.handler.OAuth2AuthenticationSuccessHandler;
import io.vikunalabs.hmp.auth.oauth2.userinfo.CustomOAuth2UserService;
import io.vikunalabs.hmp.auth.oauth2.userinfo.CustomOidcUserService;
import io.vikunalabs.hmp.auth.user.service.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfTokenRepository;

@Slf4j
@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
@EnableJpaAuditing
public class AppSecurityConfig {

    private final SessionSecurityFilter sessionSecurityFilter;
    private final CustomUserDetailsService customUserDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final SessionRegistry sessionRegistry;

    // OAuth2 and Security components
    private final CustomOAuth2UserService customOAuth2UserService; // Keep this for non-OIDC OAuth2
    private final CustomOidcUserService customOidcUserService; // NEW: Add this
    private final OAuth2AuthenticationSuccessHandler oauth2SuccessHandler;
    private final OAuth2AuthenticationFailureHandler oauth2FailureHandler;
    private final CsrfTokenRepository csrfTokenRepository;
    private final AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository;

    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(customUserDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder);
        return authProvider;
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        log.info("Configuring SecurityFilterChain with OAuth2 and OIDC...");

        return http.authenticationProvider(authenticationProvider())
                .authorizeHttpRequests(auth -> auth.requestMatchers("/api/auth/**", "/error", "/public/**")
                        .permitAll()
                        .anyRequest()
                        .authenticated())
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)

                // OAuth2 Login Configuration with BOTH OAuth2 and OIDC support
                .oauth2Login(oauth2 -> {
                    log.info("Configuring OAuth2 login with CustomOAuth2UserService and CustomOidcUserService");
                    oauth2.authorizationEndpoint(authorization ->
                                    authorization.authorizationRequestRepository(authorizationRequestRepository))
                            .userInfoEndpoint(userInfo -> {
                                log.info("Setting OAuth2 user service: {}", customOAuth2UserService);
                                log.info("Setting OIDC user service: {}", customOidcUserService);
                                userInfo.userService(customOAuth2UserService) // For regular OAuth2
                                        .oidcUserService(customOidcUserService); // For OIDC (Google)
                            })
                            .successHandler(oauth2SuccessHandler)
                            .failureHandler(oauth2FailureHandler);
                })

                // CSRF Protection
                .csrf(csrf -> csrf.csrfTokenRepository(csrfTokenRepository)
                        .ignoringRequestMatchers(
                                "/api/auth/register",
                                "/api/auth/login",
                                "/api/auth/logout",
                                "/api/auth/forgot-password",
                                "/api/auth/reset-password",
                                "/api/auth/confirm-account",
                                "/api/auth/resend-verification",
                                "/api/auth/confirm-password-token"))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        .maximumSessions(3)
                        .maxSessionsPreventsLogin(false)
                        .sessionRegistry(sessionRegistry))
                .addFilterAfter(sessionSecurityFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }
}
