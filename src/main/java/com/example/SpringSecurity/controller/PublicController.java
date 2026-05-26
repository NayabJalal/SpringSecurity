package com.example.SpringSecurity.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/public")
@RequiredArgsConstructor
public class PublicController {
    @RequestMapping("/hello")
    public ResponseEntity<?> hello(){
        return ResponseEntity.ok("Hello, this is a public endpoint accessible to everyone!");
    }
}
