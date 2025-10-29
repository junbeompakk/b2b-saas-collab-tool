// src/main/java/com/example/project/jwt/JwtUtil.java

package com.example.project.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.security.Key;
import java.util.Base64;
import java.util.Date;

@Component // Spring 컨테이너에 Bean으로 등록
public class JwtUtil {
    // 1. JWT 데이터
    // Header KEY 값. HTTP Request 헤더에 이 키로 JWT 토큰이 전달됨
    public static final String AUTHORIZATION_HEADER = "Authorization";
    // Token 식별자. 'Bearer ' 로 시작해야 함
    public static final String BEARER_PREFIX = "Bearer ";
    // 로그 설정
    private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);

    // application.properties 에서 가져올 Secret Key 값
    @Value("${jwt.secret.key}")
    private String secretKey;

    // JWT를 암호화/복호화할 때 사용할 Key 객체
    private Key key;

    // 사용할 암호화 알고리즘
    private final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

    // 2. Secret Key 초기화 (Bean이 생성될 때 한 번만 실행됨)
    @PostConstruct
    public void init() {
        byte[] bytes = Base64.getDecoder().decode(secretKey);
        key = Keys.hmacShaKeyFor(bytes);
    }

    // 3. JWT 토큰 생성
    public String createToken(String username) {
        Date date = new Date();
        long TOKEN_TIME = 60 * 60 * 1000L; // 1시간

        return BEARER_PREFIX + // "Bearer " 접두사 붙여서 반환
                Jwts.builder()
                        .setSubject(username) // 사용자 식별자값(ID)
                        .setExpiration(new Date(date.getTime() + TOKEN_TIME)) // 만료 시간
                        .setIssuedAt(date) // 발급일
                        .signWith(key, signatureAlgorithm) // 암호화 알고리즘
                        .compact(); // 압축하여 최종 JWT 문자열 생성
    }

    // 4. HTTP Header 에서 토큰 값 가져오기
    public String resolveToken(HttpServletRequest request) {
        // "Authorization" 헤더에서 "Bearer " 로 시작하는 토큰 값을 찾아옴
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_PREFIX)) {
            // "Bearer " 부분(앞 7글자)을 제거하고 순수 토큰 값만 반환
            return bearerToken.substring(7);
        }
        return null;
    }

    // 5. 토큰 검증
    public boolean validateToken(String token) {
        try {
            // 토큰의 위변조 여부, 만료 여부 등을 검사
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (SecurityException | MalformedJwtException e) {
            logger.error("Invalid JWT signature, 유효하지 않는 JWT 서명 입니다.");
        } catch (ExpiredJwtException e) {
            logger.error("Expired JWT token, 만료된 JWT token 입니다.");
        } catch (UnsupportedJwtException e) {
            logger.error("Unsupported JWT token, 지원되지 않는 JWT 토큰 입니다.");
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims is empty, 잘못된 JWT 토큰 입니다.");
        }
        return false;
    }

    // 6. 토큰에서 사용자 정보 가져오기
    public Claims getUserInfoFromToken(String token) {
        // 검증된 토큰에서 사용자 정보를 담고 있는 Claims 객체를 반환
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
    }
}