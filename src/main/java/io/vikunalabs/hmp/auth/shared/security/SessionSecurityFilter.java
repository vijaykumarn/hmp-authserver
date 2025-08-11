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

        String requestPath = request.getRequestURI();
        log.debug("SessionSecurityFilter processing: {} {}", request.getMethod(), requestPath);

        // Skip validation for public endpoints
        if (isPublicEndpoint(requestPath)) {
            log.debug("Skipping session validation for public endpoint: {}", requestPath);
            filterChain.doFilter(request, response);
            return;
        }

        // Special handling for session validation endpoints during OAuth2 callback
        if (isSessionValidationEndpoint(requestPath)) {
            log.debug("Processing session validation endpoint: {}", requestPath);

            HttpSession session = request.getSession(false);
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            // Allow the request to proceed - let the controller handle validation
            filterChain.doFilter(request, response);
            return;
        }

        // Standard session validation for other protected endpoints
        HttpSession session = request.getSession(false);
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (session != null
                && authentication != null
                && authentication.isAuthenticated()
                && !"anonymousUser".equals(authentication.getPrincipal())) {

            if (!sessionService.validateSessionSecurity(request)) {
                log.warn("Session security validation failed for request: {}", requestPath);
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
        return path.startsWith("/api/auth/")
                || path.equals("/error")
                || path.startsWith("/public/")
                || path.startsWith("/oauth2/")
                || path.startsWith("/login/oauth2/");
    }

    private boolean isSessionValidationEndpoint(String path) {
        return path.equals("/api/session/validate") || path.equals("/api/session/check");
    }
}
