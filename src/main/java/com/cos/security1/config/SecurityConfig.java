package com.cos.security1.config;

import com.cos.security1.oauth.PrincipalOauth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@RequiredArgsConstructor
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) // secured 어노테이션 활성화, preAuthorize 어노테이션 활성화
public class SecurityConfig { // WebSecurityConfigurerAdapter deprecated

    private final PrincipalOauth2UserService principalOauth2UserService;

    @Bean // 해당 메서드의 리턴되는 오브젝트를 IoC에 등록해준다.
    public BCryptPasswordEncoder encodePassword(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf().disable();

        http.authorizeRequests()
                .antMatchers("/user/**").authenticated() // /user/**는 인증만 되면 들어갈 수 있는 주소
                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll()
                .and()
                .formLogin()
                .loginPage("/loginForm")
                .loginProcessingUrl("/login") // 이 url이 호출이 되면 시큐리티가 대신 로그인을 진행해줌
                .defaultSuccessUrl("/") // /loginForm을 요청해서 로그인했을 때의 로그인 이후 url. 특정 페이지 요청해서 로그인했을 경우는 그 페이지로 보내줌
                .and()
                .oauth2Login()
                .loginPage("/loginForm") // 로그인 후처리 1.코드밥기(인증) 2.액세스토큰받기(정보접근권한) 3. 사용자프로필정보 가져오기 4. 그 정보로 회원가입하기도 함
                .userInfoEndpoint() // 구글 로그인은 코드받기x 토큰+사용자정보o
                .userService(principalOauth2UserService);

        return http.build();
    }


//
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http.csrf().disable();
//    }


}
