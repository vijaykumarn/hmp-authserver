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
import org.springframework.http.HttpMethod;
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
import org.springframework.web.cors.CorsConfigurationSource;

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
    private final CorsConfigurationSource corsConfigurationSource;

    // OAuth2 and Security components
    private final CustomOAuth2UserService customOAuth2UserService; // Keep this for non-OIDC OAuth2
    private final CustomOidcUserService customOidcUserService; // NEW: Add this
    private final OAuth2AuthenticationSuccessHandler oauth2SuccessHandler;
    private final OAuth2AuthenticationFailureHandler oauth2FailureHandler;
    private final CsrfTokenRepository csrfTokenRepository;
    private final AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository;

    private static final String[] SWAGGER_WHITELIST = {
        "/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html", "/webjars/**"
    };

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

                // CORS Configuration - MUST come first
                .cors(cors -> cors.configurationSource(corsConfigurationSource))
                .authorizeHttpRequests(auth -> auth
                        // Public endpoints
                        .requestMatchers("/api/auth/**", "/error", "/public/**", "/oauth2/**", "/login/oauth2/**")
                        .permitAll()

                        // Session endpoints - allow for OAuth2 callback validation
                        .requestMatchers(HttpMethod.GET, "/api/session/validate", "/api/session/check")
                        .permitAll()
                        // Allow swagger endpoints without authentication
                        .requestMatchers(SWAGGER_WHITELIST)
                        .permitAll()

                        // Other session endpoints require authentication
                        .requestMatchers("/api/session/**")
                        .authenticated()

                        // All other requests require authentication
                        .anyRequest()
                        .authenticated())
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)

                // OAuth2 Login Configuration
                .oauth2Login(oauth2 -> {
                    log.info("Configuring OAuth2 login");
                    oauth2.authorizationEndpoint(authorization ->
                                    authorization.authorizationRequestRepository(authorizationRequestRepository))
                            .userInfoEndpoint(userInfo -> {
                                userInfo.userService(customOAuth2UserService).oidcUserService(customOidcUserService);
                            })
                            .successHandler(oauth2SuccessHandler)
                            .failureHandler(oauth2FailureHandler);
                })

                // CSRF Protection - exclude session validation endpoints
                .csrf(csrf -> csrf.csrfTokenRepository(csrfTokenRepository)
                        .ignoringRequestMatchers(
                                "/api/auth/**",
                                "/api/session/validate",
                                "/api/session/check",
                                "/oauth2/**",
                                "/login/oauth2/**",
                                "/api/v1/security/csrf-token"))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        .maximumSessions(3)
                        .maxSessionsPreventsLogin(false)
                        .sessionRegistry(sessionRegistry))
                .addFilterAfter(sessionSecurityFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }
}
