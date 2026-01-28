package com.codeit.security.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@Slf4j
//
public class CustomAccessDeniedHandler implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException, ServletException {

        String username = request.getUserPrincipal() != null
                ? request.getUserPrincipal().getName()
                : "anonymous";

        log.warn("Access Denied: User '{}' attempted to access '{}'",
                username, request.getRequestURI());

        // JSON 요청인 경우
        if (request.getHeader("Accept") != null
                && request.getHeader("Accept").contains("application/json")) {
            response.setContentType("application/json;charset=UTF-8");
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.getWriter().write("""
                {
                  "error": "Access Denied",
                  "message": "이 리소스에 접근할 권한이 없습니다",
                  "path": "%s"
                }
                """.formatted(request.getRequestURI()));
        } else {
            // HTML 요청인 경우
            response.sendRedirect("/access-denied");
        }
    }
}
