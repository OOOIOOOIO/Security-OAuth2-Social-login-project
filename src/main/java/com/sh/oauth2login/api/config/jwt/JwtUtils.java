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

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expireMin}")
    private Long expireMin;

    /**
     * header에서 jwt-access 가져오기
     * header 이름 : jwt-auth-token
     */
    public String getJwtFromHeader(HttpServletRequest request) {

        return request.getHeader("jwt-auth-token");
    }

    /**
     * header에서 jwt-refresh 가져오기
     * header 이름 : jwt-auth-refresh-token
     */
    public String getJwtRefreshFromHeader(HttpServletRequest request) {
        return request.getHeader("jwt-auth-refresh-token");
    }



    /**
     * (구-폼)
     * JWT에서 정보 가져오기(email)
     * subject : email(헤더이름)
     */
//    public String getUserEmailFromJwtToken(String token) {
//        return Jwts.parserBuilder()
//                .setSigningKey(secret.getBytes()) // signature를 secrete key로 설정했는지, publickey로 설정했는지 확인! 나는 secret key로 설정
//                .build()
//                .parseClaimsJws(token)
//                .getBody() // getBody == claims(payload) 가져오기
//                .getSubject();
//    }

    /**
     * (신-소셜)
     * JWT에서 정보 가져오기
     * payload : email, provider
     */
    public Map<String, Object> getUserEmailAndProviderFromJwtToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(secret.getBytes()) // signature를 secrete key로 설정했는지, publickey로 설정했는지 확인! 나는 secret key로 설정
                .build()
                .parseClaimsJws(token)
                .getBody(); // getBody == claims(payload) 가져오기

    }

    /**
     *  JWT 토큰 검사
     */
    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(secret.getBytes()) // signature를 secrete key로 설정했는지, publickey로 설정했는지 확인! 나는 secret key로 설정
                    .build()
                    .parseClaimsJws(authToken);  // 여기서 Runtime Exception이 던져진다.

            return true;
        } catch (SignatureException e) {
            throw new SignatureException("Invalid JWT signature : " + e.getMessage());
        } catch (MalformedJwtException e) {
            throw new MalformedJwtException("Invalid JWT token : {}" + e.getMessage());
        } catch (ExpiredJwtException e) {
            throw new JwtTokenExpiredException("JWT token is expired : " + e.getMessage());
        } catch (UnsupportedJwtException e) {
            throw new UnsupportedJwtException("JWT token is unsupported :" + e.getMessage());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("JWT claims string is empty: " + e.getMessage());
        }

    }


    /**
     * (구-폼)
     * JWT 토큰 생성
     * subject :username
     */
//    public String generateTokenFromEmail(String email, String provider) {
//        Key key = Keys.hmacShaKeyFor(secret.getBytes());
//        Map<String, String> payloads = new HashMap<>();
//        payloads.put("email", email);
//        payloads.put("provider", provider);
//
//
//        return Jwts.builder()
//                .setHeaderParam("typ", "JWT")
//                .setHeaderParam("alg", "HS256")
//                .setSubject(email+","+provider)
//                .setClaims(payloads)
//                .setIssuedAt(new Date())
//                .setExpiration(new Date((new Date()).getTime() + expireMin))
//                .signWith(key, SignatureAlgorithm.HS256)
//                .compact();
//    }

    /**
     * (신-소셜)
     * JWT 토큰 생성
     * payload : email, provider
     */
    public String generateTokenFromEmailAndProvider(String email, String provider) {
        Key key = Keys.hmacShaKeyFor(secret.getBytes());
        Map<String, String> payloads = new HashMap<>();
        payloads.put("email", email);
        payloads.put("provider", provider);


        return Jwts.builder()
                .setHeaderParam("typ", "JWT")
                .setHeaderParam("alg", "HS256")
                .setSubject(email+","+provider)
                .setClaims(payloads)
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + expireMin))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }


}

