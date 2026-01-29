package com.codeit.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;

@Slf4j
//@Component
//@Order(1) // 다른 필터보다 먼저 실행
public class SessionIdLoggingFilter extends OncePerRequestFilter {

    protected void doFilterInternal(HttpServletRequest request,
                                HttpServletResponse response,
                                FilterChain filterChain) throws IOException, ServletException {

        // 로그인 요청인지 확인
        boolean isLoginRequest = request.getRequestURI().equals("/login")
                && request.getMethod().equals("POST");

        if (isLoginRequest) {
            HttpSession session = request.getSession(false);
            String sessionIdBefore = session != null ? session.getId() : "세션 없음";
            String username = request.getParameter("username");
            String ipAddress = getClientIP(request);
            String userAgent = request.getHeader("User-Agent");

            log.info("┌─────────────────────────────────────────────────────────┐");
            log.info("│  🔐 로그인 요청 감지                                        │");
            log.info("├─────────────────────────────────────────────────────────┤");
            log.info("│ 시도 시간: {}", Instant.now());
            log.info("│ 사용자명: {}", username);
            log.info("│ IP 주소: {}", ipAddress);
            log.info("│ User-Agent: {}", userAgent);
            log.info("│ 로그인 전 세션 ID: {}", sessionIdBefore);
            log.info("├─────────────────────────────────────────────────────────┤");

            // 다음 필터로 요청을 보내서 로그인 처리 실행
            filterChain.doFilter(request, response);

            // 로그인 후 세션 ID 확인
            session = request.getSession(false);
            String sessionIdAfter = session != null ? session.getId() : "세션 없음";

            log.info("│ 로그인 후 세션 ID: {}", sessionIdAfter);
            log.info("├─────────────────────────────────────────────────────────┤");

            // 세션 ID 변경 여부 분석
            if (session == null) {
                log.warn("│ ⚠️  경고: 로그인 후 세션이 없습니다!");
            } else if (sessionIdBefore.equals("세션 없음")) {
                log.info("│ ℹ️  정보: 새 세션이 생성되었습니다.");
            } else if (!sessionIdBefore.equals(sessionIdAfter)) {
                log.info("│ ✅ 보안: 세션 ID가 변경되었습니다!");
                log.info("│         세션 고정 공격 방어 활성화됨");
            } else {
                log.error("│ 🚨 위험: 세션 ID가 변경되지 않았습니다!");
                log.error("│         세션 고정 공격에 취약할 수 있습니다!");
                log.error("│         SecurityConfig의 sessionFixation 설정을 확인하세요!");
            }

            log.info("└─────────────────────────────────────────────────────────┘");

        } else {
            filterChain.doFilter(request, response);
        }
    }

    /*
     * 클라이언트의 실제 IP 주소 추출
     * 프록시, 로드밸런서 고려
     */
    private String getClientIP(HttpServletRequest request) {
        // X-Forwarded-For 헤더 확인 (프록시/로드밸런서 뒤에 있을 때)
        String ip = request.getHeader("X-Forwarded-For");

        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("Proxy-Client-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("WL-Proxy-Client-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("HTTP_X_FORWARDED_FOR");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("HTTP_X_FORWARDED");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("HTTP_FORWARDED_FOR");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("HTTP_FORWARDED");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }

        // X-Forwarded-For는 여러 IP를 담을 수 있음: "client, proxy1, proxy2"
        // 첫 번째 IP가 실제 클라이언트
        if (ip != null && ip.contains(",")) {
            ip = ip.split(",")[0].trim();
        }

        return ip;
    }
}
