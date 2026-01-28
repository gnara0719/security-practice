package com.codeit.security.config;

import com.codeit.security.filter.IpCheckFilter;
import com.codeit.security.filter.RequestIdFilter;
import com.codeit.security.filter.RequestLoggingFilter;
import com.codeit.security.security.CustomAccessDeniedHandler;
import com.codeit.security.security.CustomAuthenticationEntryPoint;
import com.codeit.security.security.SpaCsrfTokenRequestHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.cors.CorsConfigurationSource;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
@EnableMethodSecurity // 권한 검사를 컨트롤러의 메서드에서 전역적으로 수행하기 위한 설정
public class SecurityConfig {

    private final RequestLoggingFilter requestLoggingFilter;
    private final IpCheckFilter ipCheckFilter;
    private final RequestIdFilter requestIdFilter;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // Spring Security의 보안 필터 체인을 구성하고 조립하는 역할 (절차 규칙 설정)
    // RoleHierarchy를 매개변수로 선언하면 filterChain에서 권한 계층이 적용 (빈운 사전에 등록)
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, RoleHierarchy roleHierarchy,
                                           CustomAccessDeniedHandler deniedHandler,
                                           CustomAuthenticationEntryPoint authenticationEntryPoint,
                                           @Qualifier("corsConfigSource") CorsConfigurationSource corsConfigurationSource) throws Exception {
        http
                .cors(cors -> cors
                        .configurationSource(corsConfigurationSource)
                )
                // 인증 필터 동작 전에 로깅하기 위해 필터 추가
                .addFilterBefore(requestIdFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(ipCheckFilter, RequestIdFilter.class)
                .addFilterAfter(requestLoggingFilter, IpCheckFilter.class)

                // 특정 경로에 대한 권한을 설정
                // 위에서 아래로 순차적 평가, 먼저 매칭되면 그것을 적용
                // 구체적인 것을 위에, 일반적인 것을 아래에
                .authorizeHttpRequests( auth -> auth
                        // 공개 접근 (인증 불필요)
                        // .anonymous(): 로그인하지 않은 사용자만 허용
                        .requestMatchers("/", "/signup", "/login").permitAll()
                        .requestMatchers("/css/**", "/js/**", "/public/**").permitAll()
                        .requestMatchers("/h2-console/**").permitAll()
                        .requestMatchers("/api/auth/csrf-token").permitAll() // 토큰 발급용 엔드포인트는 로그인 없이 접근 가능

                        // ADMIN 권한 필요
                        // hasRole("ADMIN"): "ROLE_ADMIN" 권한 확인 -> 보통 얘를 사용
                        // hasAuthority("ROLE_ADMIN"): 정확히 "ROLE_ADMIN" 확인
                        .requestMatchers("/admin/**").hasRole("ADMIN")

                        // MANAGER 또는 ADMIN 권한 필요
                        .requestMatchers("/manager/**").hasAnyRole("MANAGER", "ADMIN")

                        .requestMatchers("/user/**").hasRole("USER")

                        // 나머지는 인증만 필요 (권한 무관)
                        .anyRequest().authenticated()
                )
                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint(authenticationEntryPoint) // 인증
                        .accessDeniedHandler(deniedHandler))    // 인가

                // 로그인 폼 설정 (REST)에서는 사용하지 않음
                .formLogin(form -> form.
                        loginPage("/login") // 커스텀 로그인 페이지 경로
                        .permitAll())

                // 로그아웃 설정
                .logout(logout -> logout
                        .logoutSuccessUrl("/login?logout")
                        .permitAll())

                .csrf(csrf -> csrf
                        .ignoringRequestMatchers("/h2-console/**") // H2는 CSRF 검증 제외
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()) // 쿠키에 저장 & 프론트엔드에서 읽을 수 있게 허용
                        .csrfTokenRequestHandler(new SpaCsrfTokenRequestHandler())) // 방금 만든 핸들러 등록
                .headers(headers -> headers
                        .frameOptions(frame -> frame.sameOrigin()) // 같은 사이트에서 iframe을 사용하는 것을 허용
                );

        return http.build();
    }
}
