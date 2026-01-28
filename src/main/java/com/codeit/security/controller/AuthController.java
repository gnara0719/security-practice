package com.codeit.security.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @GetMapping("/csrf-token")
    public ResponseEntity<Void> getCsrfToken() {
        // 내용은 없어도 됌
        // 이 API가 호출되는 과정에서 필터가 동작해 자동으로 쿠키를 구워줌
        return ResponseEntity.ok().build();
    }
}
