package io.vikunalabs.hmp.auth.user.service.impl;

import io.vikunalabs.hmp.auth.user.domain.LogoutReason;
import io.vikunalabs.hmp.auth.user.domain.SessionInfo;
import io.vikunalabs.hmp.auth.user.domain.User;
import io.vikunalabs.hmp.auth.user.domain.UserSession;
import io.vikunalabs.hmp.auth.user.repository.UserSessionRepository;
import io.vikunalabs.hmp.auth.user.service.SessionService;
import io.vikunalabs.hmp.auth.user.service.UserService;
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
import org.springframework.util.StringUtils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
@Service
@Transactional(readOnly = true)
public class SessionServiceImpl implements SessionService {

    private final UserService userService;
    private final UserSessionRepository sessionRepository;

    @Value("${app.session.timeout.default:3600}")
    private int defaultSessionTimeout;

    @Value("${app.session.timeout.remember-me:2592000}")
    private int rememberMeSessionTimeout;

    @Value("${app.session.max-concurrent:3}")
    private int maxConcurrentSessions;

    @Value("${app.session.require-same-ip:true}")
    private boolean requireSameIp;

    @Value("${app.session.detect-user-agent-change:true}")
    private boolean detectUserAgentChange;

    @Override
    @Transactional
    public void createSession(User user, Boolean rememberMe,
                              HttpServletRequest request, HttpServletResponse response) {
        log.debug("Creating secure session for user: {}", user.getEmail());

        // Prevent session fixation - invalidate existing session
        HttpSession oldSession = request.getSession(false);
        if (oldSession != null) {
            // Mark old session as invalid in database
            markSessionInactive(oldSession.getId(), LogoutReason.SECURITY_VIOLATION);
            oldSession.invalidate();
            log.debug("Invalidated old session to prevent session fixation");
        }

        // Check concurrent session limit
        enforceConcurrentSessionLimit(user.getId());

        // Create new session
        HttpSession session = request.getSession(true);

        // Get client information
        String clientIp = getClientIP(request);
        String userAgent = getUserAgent(request);
        String userAgentHash = hashUserAgent(userAgent);

        // Update user login information
        user.setLastLogin(Instant.now());
        user.setRememberMe(rememberMe != null && rememberMe);
        userService.save(user);

        // Create authentication
        List<SimpleGrantedAuthority> authorities = List.of(
                new SimpleGrantedAuthority("ROLE_" + user.getRole().name())
        );

        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(
                        user.getEmail(),
                        null,
                        authorities
                );

        // Set up security context
        SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
        securityContext.setAuthentication(authentication);
        SecurityContextHolder.setContext(securityContext);

        // Configure session attributes
        session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, securityContext);
        session.setAttribute("USER_ID", user.getId());
        session.setAttribute("USER_EMAIL", user.getEmail());
        session.setAttribute("CLIENT_IP", clientIp);
        session.setAttribute("USER_AGENT_HASH", userAgentHash);
        session.setAttribute("CREATED_AT", Instant.now().toString());
        session.setAttribute("REMEMBER_ME", rememberMe);

        // Set session timeout
        int sessionTimeout = (rememberMe != null && rememberMe) ? rememberMeSessionTimeout : defaultSessionTimeout;
        session.setMaxInactiveInterval(sessionTimeout);

        // Store session in database
        UserSession userSession = UserSession.builder()
                .sessionId(session.getId())
                .user(user)
                .ipAddress(clientIp)
                .userAgentHash(userAgentHash)
                .lastAccessedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(sessionTimeout))
                .rememberMe(rememberMe != null && rememberMe)
                .active(true)
                .build();

        sessionRepository.save(userSession);

        // Configure secure cookie
        configureSecureSessionCookie(response, session.getId(), sessionTimeout);

        log.info("Secure session created for user: {} (IP: {}) with timeout: {} seconds",
                user.getEmail(), clientIp, sessionTimeout);
    }

    @Override
    @Transactional
    public boolean validateSessionSecurity(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            log.debug("No session found for validation");
            return false;
        }

        try {
            // Get session from database
            Optional<UserSession> userSessionOpt = sessionRepository
                    .findBySessionIdAndActiveTrue(session.getId());

            if (userSessionOpt.isEmpty()) {
                log.warn("Session not found in database: {}", session.getId());
                return false;
            }

            UserSession userSession = userSessionOpt.get();

            // Check if session is expired
            if (userSession.isExpired()) {
                log.warn("Session expired: {}", session.getId());
                markSessionInactive(session.getId(), LogoutReason.SESSION_EXPIRED);
                return false;
            }

            // Validate IP address if required
            if (requireSameIp) {
                String currentIp = getClientIP(request);
                if (!userSession.getIpAddress().equals(currentIp)) {
                    log.warn("IP address mismatch for session: {} (stored: {}, current: {})",
                            session.getId(), userSession.getIpAddress(), currentIp);
                    markSessionInactive(session.getId(), LogoutReason.IP_ADDRESS_CHANGE);
                    return false;
                }
            }

            // Validate User-Agent if required
            if (detectUserAgentChange) {
                String currentUserAgentHash = hashUserAgent(getUserAgent(request));
                if (!userSession.getUserAgentHash().equals(currentUserAgentHash)) {
                    log.warn("User-Agent change detected for session: {}", session.getId());
                    markSessionInactive(session.getId(), LogoutReason.USER_AGENT_CHANGE);
                    return false;
                }
            }

            // Update last accessed time
            userSession.updateLastAccessed();
            sessionRepository.save(userSession);

            return true;

        } catch (Exception e) {
            log.error("Error validating session security", e);
            return false;
        }
    }

    @Override
    @Transactional
    public void invalidateSession(HttpServletRequest request, HttpServletResponse response) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            String sessionId = session.getId();

            log.debug("Invalidating session: {}", sessionId);

            // Mark session as inactive in database
            markSessionInactive(sessionId, LogoutReason.USER_LOGOUT);

            // Invalidate HTTP session
            session.invalidate();
        }

        // Clear security context
        SecurityContextHolder.clearContext();

        // Clear session cookie
        if (response != null) {
            clearSessionCookie(response);
        }

        log.info("Session invalidated successfully");
    }

    @Override
    @Transactional
    public void invalidateAllUserSessions(Long userId) {
        log.info("Invalidating all sessions for user: {}", userId);

        int invalidatedCount = sessionRepository.invalidateAllUserSessions(userId, LogoutReason.ADMIN_REVOKE);

        log.info("Invalidated {} sessions for user: {}", invalidatedCount, userId);
    }

    @Override
    @Transactional
    public void cleanupExpiredSessions() {
        log.info("Starting cleanup of expired sessions");

        // Mark expired sessions as inactive
        int markedCount = sessionRepository.markExpiredSessions(Instant.now());

        // Optional: Delete very old inactive sessions (older than 30 days)
        Instant cutoff = Instant.now().minus(30, ChronoUnit.DAYS);
        List<UserSession> oldSessions = sessionRepository.findInactiveSessions(cutoff);

        if (!oldSessions.isEmpty()) {
            sessionRepository.deleteAll(oldSessions);
            log.info("Deleted {} old inactive sessions", oldSessions.size());
        }

        log.info("Marked {} sessions as expired", markedCount);
    }

    @Override
    public SessionInfo getCurrentSessionInfo(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }

        Optional<UserSession> userSessionOpt = sessionRepository
                .findBySessionIdAndActiveTrue(session.getId());

        return userSessionOpt.map(this::mapToSessionInfo).orElse(null);
    }

    @Override
    @Transactional
    public void updateLastLogin(User user) {
        user.setLastLogin(Instant.now());
        userService.save(user);
        log.debug("Updated last login for user: {}", user.getEmail());
    }

    // Additional method to get user's active sessions
    public List<SessionInfo> getUserActiveSessions(Long userId) {
        List<UserSession> sessions = sessionRepository.findActiveSessionsByUserId(userId);
        return sessions.stream()
                .map(this::mapToSessionInfo)
                .toList();
    }

    // Private helper methods

    @Transactional
    protected void enforceConcurrentSessionLimit(Long userId) {
        long activeSessionCount = sessionRepository.countActiveSessionsByUserId(userId);

        if (activeSessionCount >= maxConcurrentSessions) {
            // Get oldest sessions and invalidate them
            List<UserSession> sessions = sessionRepository
                    .findActiveSessionsByUserIdOrderByCreatedAsc(userId);

            int sessionsToInvalidate = (int) (activeSessionCount - maxConcurrentSessions + 1);

            for (int i = 0; i < sessionsToInvalidate && i < sessions.size(); i++) {
                UserSession oldSession = sessions.get(i);
                oldSession.invalidate(LogoutReason.CONCURRENT_SESSION_LIMIT);
                sessionRepository.save(oldSession);

                log.info("Invalidated old session {} for user {} due to concurrent session limit",
                        oldSession.getSessionId(), userId);
            }
        }
    }

    @Transactional
    protected void markSessionInactive(String sessionId, LogoutReason reason) {
        sessionRepository.findBySessionIdAndActiveTrue(sessionId)
                .ifPresent(userSession -> {
                    userSession.invalidate(reason);
                    sessionRepository.save(userSession);
                });
    }

    private SessionInfo mapToSessionInfo(UserSession userSession) {
        return SessionInfo.builder()
                .sessionId(userSession.getSessionId())
                .userId(userSession.getUser().getId())
                .userEmail(userSession.getUser().getEmail())
                .ipAddress(userSession.getIpAddress())
                .userAgent(userSession.getUserAgentHash())
                .createdAt(userSession.getCreatedAt())
                .lastAccessedAt(userSession.getLastAccessedAt())
                .rememberMe(userSession.isRememberMe())
                .valid(userSession.isValid())
                .build();
    }

    private String getClientIP(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (StringUtils.hasText(xForwardedFor)) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (StringUtils.hasText(xRealIp)) {
            return xRealIp;
        }

        return request.getRemoteAddr();
    }

    private String getUserAgent(HttpServletRequest request) {
        return request.getHeader("User-Agent");
    }

    private String hashUserAgent(String userAgent) {
        if (userAgent == null) {
            return "";
        }

        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(userAgent.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            log.error("Error hashing user agent", e);
            return String.valueOf(userAgent.hashCode());
        }
    }

    private void configureSecureSessionCookie(HttpServletResponse response, String sessionId, int maxAge) {
        Cookie sessionCookie = new Cookie("JSESSIONID", sessionId);
        sessionCookie.setHttpOnly(true);
        sessionCookie.setSecure(false); // Set to true in production with HTTPS
        sessionCookie.setPath("/");
        sessionCookie.setMaxAge(maxAge);
        sessionCookie.setAttribute("SameSite", "Strict");
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

