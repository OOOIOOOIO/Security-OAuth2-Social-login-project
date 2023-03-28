package com.sh.oauth2login.api.config.jwt;

import com.sh.oauth2login.api.domain.User;
import com.sh.oauth2login.api.exception.type.JwtTokenExpiredException;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.security.Key;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtUtils {

    private final JwtInfoProperties jwtInfoProperties;
//    @Value("${jwt.secret}")
//    private String secret;
//
//    @Value("${jwt.expireMin}")
//    private Long expireMin;

    /**
     * header에서  Authorization 가져오기(access-token)
     */
    public String getJwtFromHeader(HttpServletRequest request) {

        return request.getHeader("Authorization");
    }

    /**
     * header에서 refresh-token 가져오기
     */
    public String getJwtRefreshFromHeader(HttpServletRequest request) {
        return request.getHeader("refresh-token");
    }



    /**
     * JWT에서 정보 가져오기
     * payload : email, provider
     */
    public Map<String, Object> getUserEmailAndProviderFromJwtToken(String authToken) {

        return getClaimsFromJwtToken(authToken)
                .getBody(); // getBody == claims(payload) 가져오기

    }

    /**
     * JWT Claims 가져오기
     */
    public Jws<Claims> getClaimsFromJwtToken(String authToken) {

        String jwt = subBearer(authToken);

        return Jwts.parserBuilder()
                .setSigningKey(jwtInfoProperties.getSecret().getBytes()) // signature를 secrete key로 설정했는지, publickey로 설정했는지 확인! 나는 secret key로 설정
                .build()
                .parseClaimsJws(jwt);

    }

    /**
     *  JWT 토큰 검사
     */
    public boolean validateJwtToken(String authToken) {

        String jwt = subBearer(authToken);

        try {
            Jwts.parserBuilder()
                    .setSigningKey(jwtInfoProperties.getSecret().getBytes()) // signature를 secrete key로 설정했는지, publickey로 설정했는지 확인! 나는 secret key로 설정
                    .build()
                    .parseClaimsJws(jwt);  // 여기서 Runtime Exception이 던져진다.

            return true;
        } catch (SignatureException e) {
            throw new SignatureException("Invalid JWT signature : " + e.getMessage());
        } catch (MalformedJwtException e) {
            throw new MalformedJwtException("Invalid JWT token " + e.getMessage());
        } catch (ExpiredJwtException e) {
            throw new JwtTokenExpiredException("JWT token is expired : " + e.getMessage());
        } catch (UnsupportedJwtException e) {
            throw new UnsupportedJwtException("JWT token is unsupported :" + e.getMessage());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("JWT claims string is empty: " + e.getMessage());
        }

    }


    /**
     * JWT 토큰 생성
     * payload : email, provider
     */
    public String generateTokenFromEmailAndProvider(String email, String provider) {
        Key key = Keys.hmacShaKeyFor(jwtInfoProperties.getSecret().getBytes());

        Map<String, String> payloads = new HashMap<>();
        payloads.put("email", email);
        payloads.put("provider", provider);

        return Jwts.builder()
                .setHeaderParam("typ", "JWT")
                .setHeaderParam("alg", "HS256")
                .setSubject(email+","+provider)
                .setClaims(payloads)
                .setIssuedAt(new Date())
                .setExpiration(new Date(new Date().getTime() + jwtInfoProperties.getExpireMin()))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * JWT 토큰 만료시간 검증
     */
    public void verifyExpireMin(String authToken){
        boolean before = getClaimsFromJwtToken(authToken)
                .getBody()
                .getExpiration()
                .before(new Date());

        log.error("============== ACCESS TOKEN HAS BEEN EXPIRED ==============");

        if(before){
            throw new JwtTokenExpiredException("Access token has been expired");

        }
    }

    /**
     * Access Token 추출 메서드
     */
    private String subBearer(String authToken){

        return authToken.substring("Bearer ".length());
    }


}

