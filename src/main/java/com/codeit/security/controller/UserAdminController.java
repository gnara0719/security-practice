package com.codeit.security.controller;

import com.codeit.security.domain.user.User;
import com.codeit.security.service.UserAdminService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/admin/user")
public class UserAdminController {

    private final UserAdminService userAdminService;

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping
    public List<User> listUsers() {
        List<User> allUsers = userAdminService.getAllUsers();
        return allUsers;
    }

    @PreAuthorize("#userId == authentication.principal.user.id or hasRole('ADMIN')")
    @GetMapping("/{userId}")
    public User getOneUser(@PathVariable Long userId) {
        User userById = userAdminService.getUserById(userId);
        return userById;
    }
}
