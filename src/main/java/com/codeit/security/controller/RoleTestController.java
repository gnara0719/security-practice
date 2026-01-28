package com.codeit.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RoleTestController {

    @GetMapping("/public/test")
    public String publicPage() {
        return "공개 페이지 - 누구나 접근 가능";
    }

    @GetMapping("/user/dashboard")
    public String userDashboard() {
        return "사용자 대시보드 - USER 권한 필요";
    }

    @GetMapping("/manager/reports")
    public String managerReports() {
        return "관리자 리포트 - MANAGER 권한 필요";
    }

    @GetMapping("/admin/dashboard")
    public String adminDashboard() {
        return "관리자 대시보드 - ADMIN 권한 필요";
    }
}
