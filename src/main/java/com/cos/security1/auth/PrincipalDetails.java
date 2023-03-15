package com.cos.security1.auth;

import com.cos.security1.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

// 시큐리티가 /login url을 낚아채서 로그인 진행
//로그인이 완료되면 시큐리티의 session을 생성.
// Security ContextHolder라는 키로 세션정보 저장 => 오브젝트는 Authentication 타입 객체
// Authentication 안에 user정보가 있어야 하고 User의 오브젝트 타입은 User Details 타입 객체
@RequiredArgsConstructor
public class PrincipalDetails implements UserDetails {

    private final User user;

    // 해당 유저의 권한을 리턴
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collection = new ArrayList<>();
        collection.add(() -> user.getRole()); // 람다식은 인터페이스가 하나의 메소드만을 가지고 있는 함수형 인터페이스에 대해서만 사용할 수 있습니다.

        return collection;
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
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
