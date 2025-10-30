// src/main/java/com/example/project/config/WebSecurityConfig.java

package com.example.project.config;

import com.example.project.jwt.JwtAuthenticationFilter;
import com.example.project.jwt.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity // Spring Security 지원을 가능하게 함
@RequiredArgsConstructor
public class WebSecurityConfig {

    private final JwtUtil jwtUtil;

    // 1. 비밀번호 암호화 기능 등록
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // 2. SecurityFilterChain 빈 등록 (핵심 설정)
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // CSRF(Cross-Site Request Forgery) 설정 비활성화
        http.csrf(AbstractHttpConfigurer::disable);

        // JWT 기반 인증/인가를 사용하므로, Session 관리 기능을 STATELESS로 설정
        http.sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        );

        // HTTP 요청에 대한 접근 권한 설정
        http.authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/user/**").permitAll() // '/api/user/'로 시작하는 모든 요청은 인증 없이 허용
                .anyRequest().authenticated() // 그 외 모든 요청은 인증 필요
        );

        // 직접 만든 JWT 인증 필터를 UsernamePasswordAuthenticationFilter 전에 실행하도록 설정
        http.addFilterBefore(new JwtAuthenticationFilter(jwtUtil), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}