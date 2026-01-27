package com.codeit.security.config;

import com.codeit.security.filter.IpCheckFilter;
import com.codeit.security.filter.RequestIdFilter;
import com.codeit.security.filter.RequestLoggingFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final RequestLoggingFilter requestLoggingFilter;
    private final IpCheckFilter ipCheckFilter;
    private final RequestIdFilter requestIdFilter;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // Spring Security의 보안 필터 체인을 구성하고 조립하는 역할
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // 인증 필터 동작 전에 로깅하기 위해 필터 추가
                .addFilterBefore(requestIdFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(ipCheckFilter, RequestIdFilter.class)
                .addFilterAfter(requestLoggingFilter, IpCheckFilter.class)

                // 특정 경로에 대한 권한을 설정
                .authorizeHttpRequests( auth ->
                auth.requestMatchers("/", "/h2-console/**", "/signup", "/css/**", "/js/**").permitAll()
                        .anyRequest().authenticated()
                )

                // 로그인 폼 설정 (REST)에서는 사용하지 않음
                .formLogin(form -> form.
                        loginPage("/login") // 커스텀 로그인 페이지 경로
                        .permitAll())

                // 로그아웃 설정
                .logout(logout -> logout
                        .logoutSuccessUrl("/login?logout")
                        .permitAll())

                // h2는 CSRF 검증 제외
                .csrf(csrf -> csrf.ignoringRequestMatchers("/h2-console/**"))
                .headers(headers -> headers
                        .frameOptions(frame -> frame.sameOrigin()) // 같은 사이트에서 iframe을 사용하는 것을 허용
                );

        return http.build();
    }
}
