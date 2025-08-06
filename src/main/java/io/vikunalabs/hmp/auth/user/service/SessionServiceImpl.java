package io.vikunalabs.hmp.auth.user.service;

import io.vikunalabs.hmp.auth.user.domain.UserAccount;
import io.vikunalabs.hmp.auth.user.service.SessionService;
import io.vikunalabs.hmp.auth.user.service.UserAccountService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;

@Slf4j
@RequiredArgsConstructor
@Service
@Transactional(readOnly = true)
public class SessionServiceImpl implements SessionService {

    private final UserAccountService userAccountService;

    @Value("${app.session.timeout.default:3600}") // 1 hour default
    private int defaultSessionTimeout;

    @Value("${app.session.timeout.remember-me:2592000}") // 30 days default
    private int rememberMeSessionTimeout;

    @Override
    @Transactional
    public void createSession(UserAccount userAccount, Boolean rememberMe, 
                            HttpServletRequest request, HttpServletResponse response) {
        log.debug("Creating session for user: {}", userAccount.getEmail());

        // Update last login and remember-me preference
        userAccount.setLastLogin(Instant.now());
        userAccount.setRememberMe(rememberMe != null && rememberMe);
        userAccountService.save(userAccount);

        // Create authentication token
        List<SimpleGrantedAuthority> authorities = List.of(
            new SimpleGrantedAuthority("ROLE_" + userAccount.getRole().name())
        );
        
        UsernamePasswordAuthenticationToken authentication = 
            new UsernamePasswordAuthenticationToken(
                userAccount.getEmail(), 
                null, 
                authorities
            );

        // Set up security context
        SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
        securityContext.setAuthentication(authentication);
        SecurityContextHolder.setContext(securityContext);

        // Create/configure session
        HttpSession session = request.getSession(true);
        session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, securityContext);
        session.setAttribute("USER_ID", userAccount.getId());
        session.setAttribute("USER_EMAIL", userAccount.getEmail());

        // Set session timeout based on remember-me
        int sessionTimeout = (rememberMe != null && rememberMe) ? rememberMeSessionTimeout : defaultSessionTimeout;
        session.setMaxInactiveInterval(sessionTimeout);

        // Configure session cookie
        configureCookie(response, session.getId(), sessionTimeout);

        log.info("Session created for user: {} with timeout: {} seconds", 
                userAccount.getEmail(), sessionTimeout);
    }

    @Override
    public void invalidateSession(HttpServletRequest request, HttpServletResponse response) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            log.debug("Invalidating session: {}", session.getId());
            session.invalidate();
        }

        // Clear security context
        SecurityContextHolder.clearContext();

        // Clear session cookie
        clearSessionCookie(response);

        log.info("Session invalidated successfully");
    }

    @Override
    @Transactional
    public void updateLastLogin(UserAccount userAccount) {
        userAccount.setLastLogin(Instant.now());
        userAccountService.save(userAccount);
        log.debug("Updated last login for user: {}", userAccount.getEmail());
    }

    private void configureCookie(HttpServletResponse response, String sessionId, int maxAge) {
        Cookie sessionCookie = new Cookie("JSESSIONID", sessionId);
        sessionCookie.setHttpOnly(true);
        sessionCookie.setSecure(false); // Set to true in production with HTTPS
        sessionCookie.setPath("/");
        sessionCookie.setMaxAge(maxAge);
        sessionCookie.setAttribute("SameSite", "Lax");
        response.addCookie(sessionCookie);
    }

    private void clearSessionCookie(HttpServletResponse response) {
        Cookie sessionCookie = new Cookie("JSESSIONID", "");
        sessionCookie.setHttpOnly(true);
        sessionCookie.setSecure(false); // Set to true in production with HTTPS
        sessionCookie.setPath("/");
        sessionCookie.setMaxAge(0);
        response.addCookie(sessionCookie);
    }
}