package com.example.project.jwt;

import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ActiveProfiles("test") // 테스트용 properties 파일을 사용하도록 설정
class JwtUtilTest {

    @Autowired
    private JwtUtil jwtUtil;

    private String testUsername = "testuser";

    @Test
    @DisplayName("1. JWT 토큰 생성 테스트")
    void test1() {
        // Given - When
        String token = jwtUtil.createToken(testUsername);

        // Then
        assertNotNull(token); // 토큰이 null이 아닌지 확인
        assertTrue(token.startsWith(JwtUtil.BEARER_PREFIX)); // "Bearer " 로 시작하는지 확인
        System.out.println("Generated Token: " + token);
    }

    @Test
    @DisplayName("2. 생성된 토큰 검증 테스트")
    void test2() {
        // Given
        String token = jwtUtil.createToken(testUsername).substring(7); // Bearer 접두사 제거

        // When - Then
        assertTrue(jwtUtil.validateToken(token)); // 토큰이 유효한지 확인
    }

    @Test
    @DisplayName("3. 토큰에서 사용자 정보 추출 테스트")
    void test3() {
        // Given
        String token = jwtUtil.createToken(testUsername).substring(7);

        // When
        Claims userInfo = jwtUtil.getUserInfoFromToken(token);
        String usernameFromToken = userInfo.getSubject();

        // Then
        assertEquals(testUsername, usernameFromToken); // 토큰의 subject가 testUsername과 일치하는지 확인
    }
}