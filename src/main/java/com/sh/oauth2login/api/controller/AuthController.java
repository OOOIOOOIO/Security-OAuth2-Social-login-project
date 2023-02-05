package com.sh.oauth2login.api.controller;

import com.sh.oauth2login.api.config.jwt.JwtUtils;
import com.sh.oauth2login.api.controller.dto.request.OAuthLoginInfoDto;
import com.sh.oauth2login.api.controller.dto.response.auth.MessageResponseDto;
import com.sh.oauth2login.api.controller.dto.response.auth.ReAccessTokenResponseDto;
import com.sh.oauth2login.api.controller.dto.response.auth.UserInfoResponseDto;
import com.sh.oauth2login.api.domain.RefreshToken;
import com.sh.oauth2login.api.exception.type.TokenRefreshException;
import com.sh.oauth2login.api.repository.UserRepository;
import com.sh.oauth2login.api.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.util.*;
import java.util.stream.Collectors;


//@CrossOrigin(origins = "*", maxAge = 3600) // 60분
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

//    private final AuthenticationManager authenticationManager;
//    private final UserRepository userRepository;
//    private final PasswordEncoder encoder;
    private final JwtUtils jwtUtils;
    private final RefreshTokenService refreshTokenService;


    /**
     * 소셜 로그인 성공
     * (handler에서 redirect 오는 uri)
     */
    @GetMapping("/login-success")
    public ResponseEntity<Map<String, String>> loginSuccess(@RequestParam(name = "provider") String provider){

        Map<String, String> result = new HashMap<>();
        result.put("status", "success");
        result.put("provider", provider);

        return new ResponseEntity<>(result, HttpStatus.OK);
    }

    /**
     * Access
     *
     */
    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody OAuthLoginInfoDto oAuthLoginInfo) {


        // refresh token 조회
        Optional<RefreshToken> getRefreshToken = refreshTokenService.findByEmailAndProvider(oAuthLoginInfo.getEmail(), oAuthLoginInfo.getProvider());

        // refresh token 존재한다면
        if(getRefreshToken.isPresent()){
            // 만료 시간 확인(유효할 경우 통과)
            refreshTokenService.verifyExpiration(getRefreshToken.get());

            // refreshToken 삭제
            refreshTokenService.deleteByUserId(getRefreshToken.get());
        }

        // 존재하지 않을 경우

        // refreshToken db 생성 및 저장
        RefreshToken refreshToken =  refreshTokenService.createRefreshToken(oAuthLoginInfo.getEmail(), oAuthLoginInfo.getProvider());

        // jwt 생성
        String accessToken = jwtUtils.generateTokenFromEmailAndProvider(oAuthLoginInfo.getEmail(), oAuthLoginInfo.getProvider());


        /**
         * body에 유저 정보 반환
         *
         * email
         * provider
         * accessToken
         * refreshToken
         */
        return ResponseEntity.ok()
                .body(new UserInfoResponseDto(
                        oAuthLoginInfo.getEmail(),
                        oAuthLoginInfo.getProvider(),
                        accessToken,
                        refreshToken.getToken()));

    }


//    /**
//     * 회원가입(role 필수)
//     *
//     * 기존 사용자 이름/이메일 확인
//     * 새 사용자 생성(역할을 지정하지 않은 경우 ROLE_USER 사용)
//     * UserRepository를 사용하여 사용자를 데이터베이스에 저장
//     */
//    @PostMapping("/signup")
//    public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpRequestDto signUpRequestDto) {
//
//        // 유효성 검사
//        // username
//        if (userRepository.existsByUsername(signUpRequestDto.getUsername())) {
//            return ResponseEntity.badRequest().body(new MessageResponseDto("ERROR : USERNAME IS ALREADY TAKEN")); // 400 error
//        }
//        // email
//        if (userRepository.existsByEmail(signUpRequestDto.getEmail())) {
//            return ResponseEntity.badRequest().body(new MessageResponseDto("Error: Email is already in use!"));
//        }
//
//        // 유저 생성
//        User user = new User(signUpRequestDto.getUsername(),
//                signUpRequestDto.getEmail(),
//                encoder.encode(signUpRequestDto.getPassword()));
//
//        Set<String> strRoles = signUpRequestDto.getRole();
//
//        Set<Role> roles = new HashSet<>();
//
//        if (strRoles == null) {
//            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
//                    .orElseThrow(() -> new RuntimeException("ERROR : ROLE IS NOT FOUND"));
//
//            roles.add(userRole);
//        } else {
//            strRoles.forEach(role -> {
//                switch (role) {
//                    case "admin":
//                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
//                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
//                        roles.add(adminRole);
//
//                        break;
//                    case "mod":
//                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
//                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
//                        roles.add(modRole);
//
//                        break;
//                    default:
//                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
//                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
//                        roles.add(userRole);
//                }
//            });
//        }
//
//        user.setRoles(roles);
//        userRepository.save(user);
//
//        return ResponseEntity.ok(new MessageResponseDto("USER REGISTERED SUCCESSFULLY!"));
//
//    }
//
//    /**
//     * 로그아웃
//     * 리프레쉬 토큰 삭제
//     */
//    @PostMapping("signout")
//    public ResponseEntity<?> logoutUser(){
//
//        Object principle = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
//
//        if (principle.toString() != "anonymousUser") {
//            Long userId = ((UserDetailsImpl) principle).getUserId();
//            refreshTokenService.deleteByUserId(userId);
//        }
//
//        return ResponseEntity.ok()
//                .body(new MessageResponseDto("You've been signed out!"));
//    }

    /**
     * 리프레쉬 토큰
     */

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshtoken(HttpServletRequest request) {
        // refreshToken 조회(uuid)
        String refreshToken = jwtUtils.getJwtRefreshFromHeader(request);

        // 존재한다면(시간 비교)
        if ((refreshToken != null) && (refreshToken.length() > 0)) {

            // db 조회
            return refreshTokenService.findByToken(refreshToken)
                    .map(token -> refreshTokenService.verifyExpiration(token)) // 만료시간 검증 : db에서 삭제 후 403 error
                    .map(refreshToken1 -> refreshToken1.getUser()) // 만료가 아닐 경우 그대로 토큰 리턴
                    .map(user -> {
                        // accessToken 재생성
//                        String accessToken = jwtUtils.generateTokenFromEmail(user.getEmail(), user.getProvider()); // lazy 로딩
                        String accessToken = jwtUtils.generateTokenFromEmailAndProvider(user.getEmail(), user.getProvider()); // lazy 로딩

                        // access token 리턴
                        return ResponseEntity.ok()
                                .body(new ReAccessTokenResponseDto("Token is refreshed successfully!", accessToken));
                    })
                    .orElseThrow(() -> new TokenRefreshException(refreshToken, "Refresh token is not in database!"));
        }

        return ResponseEntity.badRequest().body(new MessageResponseDto("Refresh Token is empty!"));
    }


}
