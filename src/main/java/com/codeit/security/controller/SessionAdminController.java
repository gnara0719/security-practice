package com.codeit.security.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.List;

@Controller
@Slf4j
@RequestMapping("/admin")
@RequiredArgsConstructor
public class SessionAdminController {

    private final SessionRegistry sessionRegistry;

    @GetMapping("/sessions")
    public String viewSessions(Model model) {

        // SessionRegistry에서 모든 활성 사용자(Principal) 조회
        List<Object> principals = sessionRegistry.getAllPrincipals();

        log.info("===== 활성 세션 조회 요청 =====");
        log.info("총 활성 사용자: {}", principals.size());

        List<UserSessionInfo> sessionInfos = principals.stream()
                .map(principal -> {
                    // Object 타입을 UserDetails 타입으로 캐스팅
                    UserDetails user = (UserDetails) principal;

                    // 이 사용자의 모든 세션 조회
                    List<SessionInformation> sessions
                            = sessionRegistry.getAllSessions(user, false);

                    log.info("- {}: {}개 세션", user.getUsername(), sessions.size());

                    return new UserSessionInfo(user.getUsername(), sessions.size(), sessions);
                })
                .toList();

        // 총 세션 수 계산
        int totalSessions = sessionInfos.stream()
                .mapToInt(UserSessionInfo::sessionCount)
                .sum();

        log.info("총 활성 세션: {}개", totalSessions);

        model.addAttribute("sessionInfos", sessionInfos);

        return "admin/sessions";
    }

    public record UserSessionInfo(String username,
                                  int sessionCount,
                                  List<SessionInformation> sessions) {
    }
}
