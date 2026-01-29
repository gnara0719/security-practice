package com.codeit.security.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

@Slf4j
@Component
public class CustomAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    private static final DateTimeFormatter FORMATTER
            = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
            .withZone(ZoneId.systemDefault());

    public CustomAuthenticationSuccessHandler() {
        // 기본 리다이렉트 URL 설정
        setDefaultTargetUrl("/");
        // 항상 기본 URL로 이동 여부 (저장된 요청 무시하려면 true)
        setAlwaysUseDefaultTargetUrl(true);
    }

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) throws ServletException, IOException {

        HttpSession session = request.getSession();
        String username = authentication.getName();
        Instant now = Instant.now();
        String ipAddress = getClientIP(request);
        String userAgent = request.getHeader("User-Agent");

        // 상세 로그 기록
        log.info("┌─────────────────────────────────────────────────────────┐");
        log.info("│  ✅ 인증 성공                                             │");
        log.info("├─────────────────────────────────────────────────────────┤");
        log.info("│ 사용자: {}", username);
        log.info("│ 권한: {}", authentication.getAuthorities());
        log.info("│ 세션 ID: {}", session.getId());
        log.info("│ 세션 생성 시간: {}",
                FORMATTER.format(Instant.ofEpochMilli(session.getCreationTime())));
        log.info("│ 세션 타임아웃: {}분", session.getMaxInactiveInterval() / 60);
        log.info("│ 로그인 시간: {}", FORMATTER.format(now));
        log.info("│ IP 주소: {}", ipAddress);
        log.info("│ User-Agent: {}", userAgent);
        log.info("└─────────────────────────────────────────────────────────┘");

        // 세션에 보안 정보 저장
        session.setAttribute("LOGIN_TIME", now);
        session.setAttribute("LOGIN_IP", ipAddress);
        session.setAttribute("USER_AGENT", userAgent);

        // 실무에서는 여기서 추가 작업:
        // 1. 마지막 로그인 시간을 데이터베이스에 업데이트
        // userService.updateLastLoginTime(username, now);

        // 2. 로그인 이력 저장
        // LoginHistory history = new LoginHistory(username, ipAddress, now);
        // loginHistoryRepository.save(history);

        // 3. 비밀번호 만료 체크
        // if (userService.isPasswordExpired(username)) {
        //     response.sendRedirect("/change-password");
        //     return;
        // }

        // 4. 약관 동의 확인
        // if (!userService.hasAgreedToTerms(username)) {
        //     response.sendRedirect("/terms-agreement");
        //     return;
        // }

        // 5. 알림 발송 (선택적 보안 알림)
        // notificationService.sendLoginNotification(username, ipAddress, now);

        // 부모 클래스의 리다이렉트 처리
        super.onAuthenticationSuccess(request, response, authentication);
    }

    /**
     * 클라이언트 IP 주소 추출 (프록시 고려)
     */
    private String getClientIP(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");

        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }

        if (ip != null && ip.contains(",")) {
            ip = ip.split(",")[0].trim();
        }

        return ip;
    }
}
