package io.vikunalabs.hmp.auth.user.service;

import io.vikunalabs.hmp.auth.user.domain.UserAccount;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public interface SessionService {
    
    void createSession(UserAccount userAccount, Boolean rememberMe, HttpServletRequest request, HttpServletResponse response);
    
    void invalidateSession(HttpServletRequest request, HttpServletResponse response);
    
    void updateLastLogin(UserAccount userAccount);
}