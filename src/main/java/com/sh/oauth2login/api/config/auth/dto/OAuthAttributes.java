package com.sh.oauth2login.api.config.auth.dto;

import com.sh.oauth2login.api.domain.Role;
import com.sh.oauth2login.api.domain.User;
import lombok.Builder;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;

@Slf4j
@Getter
public class OAuthAttributes {
    private Map<String, Object> attributes;
    private String nameAttributeKey;
    private String name;
    private String email;
    private String picture;
    private String provider;

    @Builder
    public OAuthAttributes(Map<String, Object> attributes, String nameAttributeKey, String name, String email, String picture, String provider) {
        this.attributes = attributes;
        this.nameAttributeKey = nameAttributeKey;
        this.name = name;
        this.email = email;
        this.picture = picture;
        this.provider = provider;
    }

    /**
     *
     * usernNameAttribute
     * @param registrationId
     * @param userNameAttributeName
     * @param attributes
     * @return OAuth2.0을 사용해 자동 로그인을 누가 하는지 판단
     * 해당 로그인인 서비스가 kakao인지 google인지 구분하여, 알맞게 매핑을 해주도록 합니다.
     * 여기서 registrationId는 OAuth2 로그인을 처리한 서비스 명("google","kakao","naver"..)이 되고,
     * userNameAttributeName은 해당 서비스의 map의 키값이 되는 값이됩니다. {google="sub", kakao="id", naver="response"}
     */
    public static OAuthAttributes of(String registrationId, String userNameAttributeName, Map<String, Object> attributes) {
        log.info("================== userNameAttributeName : " + userNameAttributeName + " ==================");
        // Naver
        if ("naver".equals(registrationId)) {
            return ofNaver("id", attributes);
        } else if ("kakao".equals(registrationId)) {
            return ofKakao("id", attributes);
        }

        // Google
        return ofGoogle(userNameAttributeName, attributes);
    }

    private static OAuthAttributes ofKakao(String userNameAttributeName, Map<String, Object> attributes) {

        log.info("========== 카카오 로그인=========");

        Map<String, ?> attributesProperties = (Map)attributes.get("properties");
        Map<String, ?> attributesKakaoAcount = (Map)attributes.get("kakao_account");

        String name = (String) attributesProperties.get("nickname");
        String picture = (String) attributesProperties.get("profile_image");
        String email = "empty";

        if ((boolean) attributesKakaoAcount.get("has_email")) {
            email = (String) attributesKakaoAcount.get("email");
        }


        return OAuthAttributes.builder()
                .name(name)
                .email(email)
                .picture(picture)
                .attributes(attributes)
                .nameAttributeKey(userNameAttributeName)
                .provider("kakao")
                .build();
    }

    /**
     *
     * @param userNameAttributeName
     * @param attributes
     * @return 구글 생성자, 구글로 로그인할 때 사용
     */
    public static OAuthAttributes ofGoogle(String userNameAttributeName, Map<String, Object> attributes){

        log.info("========== 구글 로그인=========");
        return OAuthAttributes.builder()
                .name((String) attributes.get("name"))
                .email((String) attributes.get("email"))
                .picture((String) attributes.get("picture"))
                .attributes(attributes)
                .nameAttributeKey(userNameAttributeName)
                .provider("google")
                .build();
    }

    /**
     *
     * @param userNameAttributeName
     * @param attributes
     * @return 네이버 생성자, 네이버로 로그인할 때 사용
     */
    public static OAuthAttributes ofNaver(String userNameAttributeName, Map<String, Object> attributes){

        log.info("========== 네이버 로그인 =========");

        Map<String, Object> response = (Map<String, Object>) attributes.get("response"); // 네이버 로그인 시 response에 json형태로 정보가담겨져 있다.

        return OAuthAttributes.builder()
                .name((String) response.get("name"))
                .email((String) response.get("email"))
                .picture((String) response.get("profile_image"))
                .attributes(response)
                .nameAttributeKey(userNameAttributeName)
                .provider("naver")
                .build();
    }


    public User toEntity(){
        return User.builder()
                .name(name)
                .email(email)
                .picture(picture)
//                .role(Role.GUEST) // 처음 가입할 때(로그인할 때) GUEST권한 부여
                .role(Role.USER)
                .provider(provider)
                .build();
    }
}
