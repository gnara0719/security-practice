package com.codeit.security.event;

import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpSessionEvent;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.session.HttpSessionDestroyedEvent;
import org.springframework.stereotype.Component;

import java.time.Instant;

@Slf4j
@Component
public class SessionEventListener {

    @EventListener
    public void onSessionCreated(HttpSessionEvent event) {
        HttpSession session = event.getSession();

        log.info("=== 새 세션 생성 ===");
        log.info("세션 ID: {}", session.getId());
        log.info("생성 시간: {}", Instant.ofEpochMilli(session.getCreationTime()));
        log.info("최대 비활성 시간: {}분", session.getMaxInactiveInterval() / 60);
    }

    @EventListener
    public void onSessionDestroyed(HttpSessionDestroyedEvent event) {
        HttpSession session = event.getSession();

        log.info("=== 세션 소멸 ===");
        log.info("세션 ID: {}", session.getId());

        SecurityContext context = (SecurityContext) session.getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);

        if (context != null && context.getAuthentication() != null) {
            log.info("사용자: {}", context.getAuthentication().getName());
            log.info("로그아웃 시간: {}", Instant.now());
        }

    }
}
