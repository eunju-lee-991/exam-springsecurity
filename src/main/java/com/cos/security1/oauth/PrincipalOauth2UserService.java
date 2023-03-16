package com.cos.security1.oauth;

import com.cos.security1.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.oauth.provider.GoogleUserInfo;
import com.cos.security1.oauth.provider.NaverUserInfo;
import com.cos.security1.oauth.provider.OAuth2UserInfo;
import com.cos.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {
    private final UserRepository userRepository;


    // userRequest 정보로 회원프로필 받아오는 게 loadUser 함수. 구글로부터 받은 userRequest 데이터에 대한 후처리 함수
    // 함수 종료시 @AuthenticationPrincipal 어노테이션이 만들어진다
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
//        userRequest.getClientRegistration() // 어떤 oAuth로 로그인했는지 확인 가능
//        userRequest.getAccessToken(); // 로그인 후 code 받은 것을 OAuth-client 라이브러리가 받아서 AccessToken 요청 -> userRequest 정보 받음
        String providerName = userRequest.getClientRegistration().getRegistrationId();
        OAuth2User oauth2User = super.loadUser(userRequest);
        OAuth2UserInfo oAuth2UserInfo = null;

        if (providerName.equals("google")) {
            oAuth2UserInfo = new GoogleUserInfo(oauth2User.getAttributes());
        } else if (providerName.equals("naver")) {
            oAuth2UserInfo = new NaverUserInfo((Map)oauth2User.getAttributes().get("response"));
        }else {

        }

        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();

        String provider = oAuth2UserInfo.getProvider();
        String providerId = oAuth2UserInfo.getProviderId();
        String username = provider + "_" + providerId;
        String password = bCryptPasswordEncoder.encode("getinthere");
        String email = oAuth2UserInfo.getEmail();
        String role = "ROLE_USER";

        User user = userRepository.findByUsername(username);

        if (user == null) {
            user = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
                    userRepository.save(user);
        }
        return new PrincipalDetails(user, oauth2User.getAttributes());
    }
}
