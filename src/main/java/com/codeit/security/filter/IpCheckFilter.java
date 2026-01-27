package com.codeit.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
@Slf4j
public class IpCheckFilter extends OncePerRequestFilter {

    // 실습용: 차단할 IP 목록 (실제로는 DB나 설정 파일에서 관리)
    private static final List<String> BLOCKED_IPS = List.of(
            "192.168.1.100"
            // 필요시 추가
    );

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String clientIp = getClientIp(request);
        log.debug("Client IP: {}", clientIp);

        // IP 차단 체크
        if (BLOCKED_IPS.contains(clientIp)) {
            log.warn("Blocked IP tried to access: {}", clientIp);
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.getWriter().write("Access Denied");
            return;  // 필터 체인 중단
        }

        // 정상적인 경우 다음 필터로 전달
        filterChain.doFilter(request, response);
    }

    private String getClientIp(HttpServletRequest request) {
        // Proxy나 Load Balancer를 거친 경우 실제 IP 추출
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("Proxy-Client-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("WL-Proxy-Client-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        return ip;
    }

    // 특정 요청을 필터링해서 제외하는 메서드
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // 특정 경로는 IP 체크 제외 (예: 공개 API)
        String path = request.getRequestURI();
        return path.startsWith("/public/");
    }
}
