package com.codeit.security.event;

import com.codeit.security.security.CustomUserDetails;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Slf4j
@Component
public class AuthenticationSuccessListener {

    @EventListener
    public void onAuthenticationSuccess(AuthenticationSuccessEvent event) {
        Object principal = event.getAuthentication().getPrincipal();

        if (principal instanceof CustomUserDetails userDetails) {
            log.info("=== 로구인 성공 ===");
            log.info("사용자: {}", userDetails.getUsername());
            log.info("시간: {}", LocalDateTime.now());
            log.info("권한: {}", event.getAuthentication().getAuthorities());
        }
    }
}
