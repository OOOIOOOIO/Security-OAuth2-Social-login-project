package com.sh.oauth2login.api.config.auth.handler;

import com.sh.oauth2login.api.config.auth.dto.OauthUserDto;
import com.sh.oauth2login.api.config.jwt.JwtUtils;
import com.sh.oauth2login.api.domain.RefreshToken;
import com.sh.oauth2login.api.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Provider;
import java.util.Map;
import java.util.Optional;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandlerImpl implements AuthenticationSuccessHandler {

    private final JwtUtils jwtUtils;
    private final RefreshTokenService refreshTokenService;


    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        String[] path = request.getRequestURI().split("/");
        String provider = path[path.length-1];

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        Map<String, Object> attributes = oAuth2User.getAttributes();
        String email = null;

        if (provider.equals("naver") || provider.equals("google")) {
            email = (String) attributes.get("email");
        }
        else{
            Map<String, ?> attributesKakaoAcount = (Map)attributes.get("kakao_account");
            email = (String) attributesKakaoAcount.get("email");

        }

        log.info("=========== " + provider + " 소셜 로그인 성공" + " ===============");
        log.info("=========== 이메일 : " + email + " ===============");


        // refresh token 조회
        Optional<RefreshToken> getRefreshToken = refreshTokenService.findByEmailAndProvider(email, provider);

        // refresh token 존재한다면
        if(getRefreshToken.isPresent()){
            // 만료 시간 확인(유효할 경우 통과)
            refreshTokenService.verifyExpiration(getRefreshToken.get());

            // refreshToken 삭제
            refreshTokenService.deleteByUserId(getRefreshToken.get());
        }

        // 존재하지 않을 경우

        // refreshToken db 생성 및 저장
        RefreshToken refreshToken =  refreshTokenService.createRefreshToken(email, provider);
        log.info("=========== refresh token 생성 : " + refreshToken.getToken() + " ===============");

        // jwt 생성
        String accessToken = jwtUtils.generateTokenFromEmailAndProvider(email, provider);
        log.info("=========== access token 생성 : " + accessToken + " ===============");


        String uri = UriComponentsBuilder.fromUriString("http://localhost:9999/api/auth/login-success")

                .queryParam("accessToken", accessToken)
                .queryParam("refreshToken", refreshToken.getToken())
                .build().toUriString();

        response.sendRedirect(uri);



    }
}
