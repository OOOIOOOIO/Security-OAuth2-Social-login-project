package com.sh.oauth2login.api.config.jwt;

import com.sh.oauth2login.api.config.auth.CustomUserDetailsService;
import com.sh.oauth2login.api.exception.type.RefreshTokenExpiredException;
import com.sh.oauth2login.api.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

/**
 * doFilterInternal() 내부에서 수행하는 작업:
 * – HTTP 쿠키 or 헤더에서 JWT 가져오기
 * – 요청에 JWT가 있으면 유효성을 검사하고 사용자 이름을 구문 분석합니다.
 * – 사용자 이름에서 UserDetails를 가져와 인증 개체를 만듭니다.
 * – setAuthentication(authentication) 메서드를 사용하여 SecurityContext에서 현재 UserDetails를 설정합니다.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AuthTokenFilter extends OncePerRequestFilter {

    private final JwtUtils jwtUtils;
    private final CustomUserDetailsService userDetailsService;
    private final RefreshTokenService refreshTokenService;


    @Override

    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // request : 헤더에서 넘어오는 JWT
        String authToken = jwtUtils.getJwtFromHeader(request);

        // authToken 토큰(access token) 검사
        if (authToken != null && jwtUtils.validateJwtToken(authToken)) {

            // refresh token 만료시간 검증
            String jwtRefreshFromHeader = jwtUtils.getJwtRefreshFromHeader(request);
            refreshTokenService.verifyExpiration(refreshTokenService.findByToken(jwtRefreshFromHeader).orElseThrow(() -> new RefreshTokenExpiredException(jwtRefreshFromHeader, "Refresh token is not in database!")));


            // payload 에서 가져오기
            Map<String, Object> claims = jwtUtils.getUserEmailAndProviderFromJwtToken(authToken);
            String email = (String) claims.get("email");
            String provider = (String) claims.get("provider");

            // access token 만료시간 검사
            jwtUtils.verifyExpireMin(authToken);

            UserDetails userDetails = userDetailsService.loadUserByUsernameAndProvider(email, provider); // db에서 유저 조회



            // 여기서 토큰 SecurityContext에 넣기
            // SecurityContextHolder : 얘는 일회성 메모리
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                    userDetails,
                    null,
                    userDetails.getAuthorities());

            authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authenticationToken);

        }

        filterChain.doFilter(request, response);
    }



}