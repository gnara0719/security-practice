package com.codeit.security.controller;

import com.codeit.security.dto.request.SignupRequest;
import com.codeit.security.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@RequiredArgsConstructor
public class SignupController {

    private final UserService userService;

    // 화면 전환용 메서드
    @GetMapping("/signup")
    public String signup(Model model) {
        // DTO 객체를 생성해서 signupRequest라는 이름으로 model에 담아 화면단에 전달 -> 사용자의 입력값을 DTO로 한번에 받아내기 위해서.
        model.addAttribute("signupRequest", new SignupRequest());
        return "signup";
    }

    // 회원가입
    @PostMapping("/signup")
    public String signup(@Valid @ModelAttribute SignupRequest request,
                         BindingResult bindingResult) {
        // 유효성 검증에 실패한다면 signup.html로 화면 전환
        if (bindingResult.hasErrors()) {
            return "signup";
        }

        userService.signup(request);
        return "redirect:/login"; // 로그인 페이지로 리다이렉트
    }

}
