package io.vikunalabs.hmp.auth.shared.security;

import io.vikunalabs.hmp.auth.user.service.SessionService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Slf4j
@RequiredArgsConstructor
@Component
@Order(2)
public class SessionSecurityFilter extends OncePerRequestFilter {

    private final SessionService sessionService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // Skip validation for public endpoints
        String requestPath = request.getRequestURI();
        if (isPublicEndpoint(requestPath)) {
            filterChain.doFilter(request, response);
            return;
        }

        // Check if session exists first, then validate authentication
        HttpSession session = request.getSession(false);
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // If there's a session but no authentication, or authentication exists but is not authenticated
        if (session != null
                && (authentication == null
                        || !authentication.isAuthenticated()
                        || "anonymousUser".equals(authentication.getPrincipal()))) {

            if (!sessionService.validateSessionSecurity(request)) {
                log.warn("Session security validation failed for request: {}", requestPath);
                // Clear any existing invalid session
                session.invalidate();
                SecurityContextHolder.clearContext();

                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType("application/json");
                response.getWriter()
                        .write(
                                "{\"success\":false,\"error\":\"INVALID_SESSION\",\"message\":\"Session validation failed\"}");
                return;
            }
        }

        // If user is properly authenticated, validate session security
        if (authentication != null
                && authentication.isAuthenticated()
                && !"anonymousUser".equals(authentication.getPrincipal())) {

            if (!sessionService.validateSessionSecurity(request)) {
                log.warn("Session security validation failed for authenticated user: {}", requestPath);
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType("application/json");
                response.getWriter()
                        .write(
                                "{\"success\":false,\"error\":\"INVALID_SESSION\",\"message\":\"Session validation failed\"}");
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private boolean isPublicEndpoint(String path) {
        return path.startsWith("/api/auth/") || path.equals("/error") || path.startsWith("/public/");
    }
}
