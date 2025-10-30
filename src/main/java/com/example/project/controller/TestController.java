// src/main/java/com/example/project/controller/TestController.java
package com.example.project.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/test")
public class TestController {

    // 1. 인증 없이 접근 가능한 API
    @GetMapping("/public")
    public String getPublicResource() {
        return "This is a public resource.";
    }

    // 2. 인증이 필요한 API
    @GetMapping("/secure")
    public String getSecureResource() {
        // SecurityContextHolder에서 현재 인증된 사용자 정보를 가져옵니다.
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();

        return "This is a secure resource. Accessed by: " + username;
    }
}