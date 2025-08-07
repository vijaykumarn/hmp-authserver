package io.vikunalabs.hmp.auth.shared.security;

import io.vikunalabs.hmp.auth.user.service.SessionService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
@Component
@Order(2)
public class SessionSecurityFilter extends OncePerRequestFilter {

    private final SessionService sessionService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        // Skip validation for public endpoints
        String requestPath = request.getRequestURI();
        if (isPublicEndpoint(requestPath)) {
            filterChain.doFilter(request, response);
            return;
        }

        // Validate session security if user is authenticated
        if (SecurityContextHolder.getContext().getAuthentication() != null 
            && SecurityContextHolder.getContext().getAuthentication().isAuthenticated()) {
            
            if (!sessionService.validateSessionSecurity(request)) {
                log.warn("Session security validation failed for request: {}", requestPath);
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("{\"success\":false,\"error\":\"INVALID_SESSION\",\"message\":\"Session validation failed\"}");
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private boolean isPublicEndpoint(String path) {
        return path.startsWith("/api/auth/") || 
               path.equals("/error") ||
               path.startsWith("/public/");
    }
}