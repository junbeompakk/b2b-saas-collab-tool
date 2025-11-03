// src/test/java/com/example/project/controller/SecurityIntegrationTest.java
package com.example.project.controller;

import com.example.project.jwt.JwtUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@ActiveProfiles("test")
@AutoConfigureMockMvc // MockMvc를 주입받기 위해 필요
class SecurityIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtUtil jwtUtil;

    private String testUsername = "testuser";
    private String token;

    @BeforeEach
    void setUp() {
        // 각 테스트 실행 전에 테스트용 토큰을 생성
        token = jwtUtil.createToken(testUsername);
    }

    @Test
    @DisplayName("Public API 접근 테스트 (성공)")
    void publicApiAccess_Success() throws Exception {
        mockMvc.perform(get("/api/test/public"))
                .andExpect(status().isOk())
                .andExpect(content().string("This is a public resource."))
                .andDo(print());
    }

    @Test
    @DisplayName("Secure API 접근 테스트 (실패 - 토큰 없음)")
    void secureApiAccess_Failure_NoToken() throws Exception {
        mockMvc.perform(get("/api/test/secure"))
                .andExpect(status().isUnauthorized()) // 401 Unauthorized 응답을 기대
                .andDo(print());
    }

    @Test
    @DisplayName("Secure API 접근 테스트 (성공 - 유효한 토큰)")
    void secureApiAccess_Success_WithValidToken() throws Exception {
        mockMvc.perform(get("/api/test/secure")
                        .header(HttpHeaders.AUTHORIZATION, token)) // "Authorization" 헤더에 토큰 추가
                .andExpect(status().isOk())
                .andExpect(content().string("This is a secure resource. Accessed by: " + testUsername))
                .andDo(print());
    }
}