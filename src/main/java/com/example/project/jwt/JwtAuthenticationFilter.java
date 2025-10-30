// src/main/java/com/example/project/jwt/JwtAuthenticationFilter.java
package com.example.project.jwt;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j(topic = "JWT 검증 및 인가")
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // 헤더에서 JWT 토큰을 받아옵니다.
        String token = jwtUtil.resolveToken(request);

        if (token != null) {
            // 토큰이 유효한지 검증합니다.
            if (jwtUtil.validateToken(token)) {
                // 토큰에서 사용자 정보를 추출합니다.
                Claims userInfo = jwtUtil.getUserInfoFromToken(token);

                // 인증 객체를 생성하고 SecurityContext에 저장합니다.
                setAuthentication(userInfo.getSubject());
            } else {
                // 토큰이 유효하지 않을 경우의 처리
                log.error("유효하지 않은 토큰입니다.");
                response.setStatus(401); // Unauthorized 상태 코드 설정
                return; // 필터 체인 진행 중단
            }
        }

        // 다음 필터로 요청을 전달합니다.
        filterChain.doFilter(request, response);
    }

    // 인증 처리 메서드
    public void setAuthentication(String username) {
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        // UserDetails를 직접 생성하지 않고, 사용자 이름만으로 인증 객체를 만듭니다.
        // 실제로는 UserDetailsService를 통해 UserDetails 객체를 받아와야 합니다. (향후 구현 예정)
        Authentication authentication = new UsernamePasswordAuthenticationToken(username, null, null);
        context.setAuthentication(authentication);

        SecurityContextHolder.setContext(context);
    }
}