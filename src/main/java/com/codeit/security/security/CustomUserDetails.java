package com.codeit.security.security;

import com.codeit.security.domain.user.User;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.Objects;

@Getter
@RequiredArgsConstructor
public class CustomUserDetails implements UserDetails {

    private final User user;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // 유저의 권한(Role)을 리턴하는 곳
        // GrantedAuthority 형태로 변환해서 저장, 접두어로 ROLE_ 를 붙여서 저장
        return List.of(new SimpleGrantedAuthority("ROLE_" + user.getRole()));
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isEnabled() {
        return user.isEnabled();
    }

    // 나중에 컨트롤러에서 필요할 때 진짜 유저 정보를 꺼내기 위한 getter
    public User getUser() {
        return user;
    }

    /*
    크롬 로그인: User 객체 A (ID: user, 주소: 0x10)
    사파리 로그인: User 객체 B (ID: user, 주소: 0x20)

    -equals()를 재정의하지 않으면 자바는 주소값으로 비교, ID가 같더라도 주소가 다르기 때문에 서로 다른 계정으로 인식
     */

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CustomUserDetails that = (CustomUserDetails) o;
        // DB의 유니크한 ID나 username으로 비교
        return Objects.equals(user.getUsername(), that.user.getUsername());
    }

    @Override
    public int hashCode() {
        return Objects.hash(user.getUsername());
    }
}
