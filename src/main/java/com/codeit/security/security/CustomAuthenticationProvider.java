package com.codeit.security.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@Slf4j
@RequiredArgsConstructor
// UserDetailsService와 PasswordEncoder를 시큐리티가 자체적으로 알아서 인증과정에서 사용했는데,
// 그것을 직접 제어해서 실제로 로그인을 시켜줄지 말지를 결정하는 객체
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

        log.debug("인증 시도: {}", username);

        // 1. 사용자 조회
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        // 2. 비밀번호 검증
        // 절대로 ==이나 String의 equals를 쓰면 안됌. passwordEncoder의 matches로 패턴을 비교해야 함.
        if (!passwordEncoder.matches(password, userDetails.getPassword())) {
            log.warn("비밀번호 불일치: {}", username);
            throw new BadCredentialsException("비밀번호가 일치하지 않습니다");
        }

        // 3. 추가 검증 (예: 계정 상태 확인)
        if (!userDetails.isEnabled()) {
            log.warn("비활성화된 계정: {}", username);
            throw new BadCredentialsException("비활성화된 계정입니다");
        }

        log.info("인증 성공: {}", username);

        // 4. Authentication 객체 생성
        return new UsernamePasswordAuthenticationToken(
                userDetails,
                password,   // 실무에서는 password는 잘 넣지 않음
                userDetails.getAuthorities()
        );
    }

    @Override
    public boolean supports(Class<?> authentication) {
        // UsernamePasswordAuthenticationToken을 처리할 수 있음을 명시
        // 나중에 인증 방식이 JWT나 소셜 로그인이라면 이 provider가 인증하는 것을 거절함
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
