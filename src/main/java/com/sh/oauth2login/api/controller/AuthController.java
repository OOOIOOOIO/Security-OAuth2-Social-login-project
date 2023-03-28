package com.sh.oauth2login.api.controller;

import com.sh.oauth2login.api.config.jwt.JwtUtils;
import com.sh.oauth2login.api.controller.dto.response.auth.ReAccessTokenResponseDto;
import com.sh.oauth2login.api.controller.dto.response.auth.UserInfoResponseDto;
import com.sh.oauth2login.api.domain.RefreshToken;
import com.sh.oauth2login.api.exception.ErrorMessage;
import com.sh.oauth2login.api.exception.type.RefreshTokenNotFoundException;
import com.sh.oauth2login.api.resolver.UserInfoFromHeader;
import com.sh.oauth2login.api.resolver.UserInfoFromHeaderDto;
import com.sh.oauth2login.api.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.*;


//@CrossOrigin(origins = "*", maxAge = 3600) // 60분
@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final JwtUtils jwtUtils;
    private final RefreshTokenService refreshTokenService;


    /**
     * 소셜 로그인 성공
     * (handler에서 redirect 오는 uri)
     */
    @GetMapping("/login-success")
    public ResponseEntity<UserInfoResponseDto> loginSuccess(@RequestParam(name = "accessToken") String accessToken, @RequestParam(name = "refreshToken") String refreshToken){
        log.info("============ 소셜 로그인 성공 후 redirect ===============");

        return new ResponseEntity<>(new UserInfoResponseDto(accessToken, refreshToken), HttpStatus.OK);
    }




    /**
     * Access token 만료
     * J005 일 때
     * J002 ~ J004 -> 다시 로그인 시키자!
     * 토큰 만료 시 Access token
     *
     */
    @PostMapping("/re-access-token")
    public ResponseEntity<?> reAccessToken(HttpServletRequest request, @UserInfoFromHeader UserInfoFromHeaderDto userInfoFromHeaderDto) {

        log.warn("========== ACCESS TOKEN HAS BEEN EXPIRED =============");

        // refreshToken 조회(uuid)
        String refreshToken = jwtUtils.getJwtRefreshFromHeader(request);

        // 존재한다면(시간 비교)
        if ((refreshToken != null) && (refreshToken.length() > 0)) {

            String email = userInfoFromHeaderDto.getEmail();
            String provider = userInfoFromHeaderDto.getProvider();

            // refresh token db 조회 및 검증
            RefreshToken getRefreshToken = refreshTokenService.findByToken(refreshToken).orElseThrow(() -> new RefreshTokenNotFoundException(refreshToken, "Refresh token is not in database!"));
            refreshTokenService.verifyExpiration(getRefreshToken);

            String accessToken = jwtUtils.generateTokenFromEmailAndProvider(email, provider);
            log.info("=========== ACCESS TOKEN GENERATED SUCCESSFULLY : " + accessToken + " ===============");

            return new ResponseEntity<>(new ReAccessTokenResponseDto("Token is refreshed successfully!", accessToken), HttpStatus.OK);



        }

        log.error("=============== REFRESH TOKEN IS EMPTY(NOT IN DATABASE) ===============");

        return new ResponseEntity<>(new ErrorMessage("J001", new Date(), "Refresh Token is empty!", "api/auth/re-access-token"), HttpStatus.BAD_REQUEST);
    }

    /**
     * Refresh Token 만료
     *
     * J001, J006 일 때
     * 403 에러 타기 전 db에서 삭제됨
     */
    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(HttpServletRequest request, @UserInfoFromHeader UserInfoFromHeaderDto userInfoFromHeaderDto) {

        log.warn("======== REFRESH TOKEN HAS BEEN EXPIRED ==========");

        String email = userInfoFromHeaderDto.getEmail();
        String provider = userInfoFromHeaderDto.getProvider();

        // refreshToken db 생성 및 저장
        RefreshToken refreshToken =  refreshTokenService.createRefreshToken(email, provider);
        log.info("=========== REFRESH TOKEN GENERATED SUCCESSFULLY : " + refreshToken.getToken() + " ===============");

        // access token jwt 생성
        String accessToken = jwtUtils.generateTokenFromEmailAndProvider(email, provider);
        log.info("=========== ACCESS TOKEN GENERATED SUCCESSFULLY : " + accessToken + " ===============");


        return new ResponseEntity<>(new UserInfoResponseDto(accessToken, refreshToken.getToken()), HttpStatus.OK);
    }




}
