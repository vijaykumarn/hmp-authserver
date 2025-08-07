package io.vikunalabs.hmp.auth.user.service;

import io.vikunalabs.hmp.auth.user.domain.SessionInfo;
import io.vikunalabs.hmp.auth.user.domain.User;
import io.vikunalabs.hmp.auth.user.domain.UserSession;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.util.List;

public interface SessionService {
    
    void createSession(User user, Boolean rememberMe, HttpServletRequest request, HttpServletResponse response);
    
    void invalidateSession(HttpServletRequest request, HttpServletResponse response);
    
    void updateLastLogin(User user);
    
    // New security methods
    boolean validateSessionSecurity(HttpServletRequest request);
    
    void invalidateAllUserSessions(Long userId);
    
    void cleanupExpiredSessions();
    
    SessionInfo getCurrentSessionInfo(HttpServletRequest request);

     List<SessionInfo> getUserActiveSessions(Long userId);
}