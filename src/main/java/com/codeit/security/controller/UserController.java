package com.codeit.security.controller;

import com.codeit.security.domain.user.User;
import com.codeit.security.security.CustomUserDetails;
import com.codeit.security.security.SecurityUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.HashMap;
import java.util.Map;

@Controller
@RequestMapping("/users")
@RequiredArgsConstructor
@Slf4j
public class UserController {

    // 방법 1: SecurityUtils 사용
    @GetMapping("/profile")
    public String profile(Model model) {
        User user = SecurityUtils.getCurrentUser()
                .orElseThrow(() -> new IllegalStateException("로그인이 필요합니다."));

        log.info("profile accessed by: {}", user.getUsername());

        model.addAttribute("user", user);
        return "user/profile";
    }

    // 방법 2: @AuthenticationPrincipal 사용
    @GetMapping("/info")
    @ResponseBody
    public Map<String, Object> userInfo(@AuthenticationPrincipal CustomUserDetails userDetails) {
        // @AuthenticationPrincipal: 로그인한 사용자 정보를 컨트롤러 파라미터로 바로 꽂아주는 어노테이션 (SecurityUtils를 대신)
        User user = userDetails.getUser();

        Map<String, Object> info = new HashMap<>();
        info.put("id", user.getId());
        info.put("username", user.getUsername());
        info.put("email", user.getEmail());
        info.put("role", user.getRole());

        return info;
    }
}
