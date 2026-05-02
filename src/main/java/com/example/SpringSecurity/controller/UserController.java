package com.example.SpringSecurity.controller;

import com.example.SpringSecurity.entity.User;
import com.example.SpringSecurity.service.RegisterUserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/user")
@RequiredArgsConstructor
public class UserController {

    private final RegisterUserService registerUserService;

    @GetMapping("/profile")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')") // Allow both USER and ADMIN roles to access this endpoint
    public ResponseEntity<?> getUserProfile(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        String email = authentication.getName();
        User user = registerUserService.findByEmail(email);
        return ResponseEntity.ok(user);
    }
}
