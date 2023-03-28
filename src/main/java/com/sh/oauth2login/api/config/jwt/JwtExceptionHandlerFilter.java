package com.sh.oauth2login.api.config.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sh.oauth2login.api.exception.errorcode.AuthCustomErrorCode;
import com.sh.oauth2login.api.exception.errorcode.GlobalCustomErrorCode;
import com.sh.oauth2login.api.exception.type.JwtTokenExpiredException;
import com.sh.oauth2login.api.exception.type.RefreshTokenExpiredException;
import com.sh.oauth2login.api.exception.type.RefreshTokenNotFoundException;
import io.jsonwebtoken.security.SignatureException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;


@Component
@Slf4j
public class JwtExceptionHandlerFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)  throws ServletException, IOException {

        try {
            filterChain.doFilter(request, response);
        } catch (SignatureException e) {
            log.error(e.getMessage());
            errorResponse(request, response, e, AuthCustomErrorCode.SignatureException.code());
        } catch (MalformedJwtException e) {
            log.error(e.getMessage());
            errorResponse(request, response, e, AuthCustomErrorCode.MalformedJwtException.code());
        } catch (JwtTokenExpiredException e) {
            log.error(e.getMessage());
            errorResponse(request, response, e, AuthCustomErrorCode.JwtTokenExpiredException.code());
        } catch (UnsupportedJwtException e) {
            log.error(e.getMessage());
            errorResponse(request, response, e, AuthCustomErrorCode.UnsupportedJwtException.code());
        } catch (IllegalArgumentException e) {
            log.error(e.getMessage());
            errorResponse(request, response, e, GlobalCustomErrorCode.IllegalArgumentException.code());
        } catch (UsernameNotFoundException e) {
            log.error(e.getMessage());
            errorResponse(request, response, e, AuthCustomErrorCode.UsernameNotFoundException.code());
        } catch (RefreshTokenNotFoundException e) {
            log.error(e.getMessage());
            errorResponse(request, response, e, AuthCustomErrorCode.RefreshTokenNotFoundException.code());
        } catch (RefreshTokenExpiredException e) {
            log.error(e.getMessage());
            errorResponse(request, response, e, AuthCustomErrorCode.RefreshTokenExpiredException.code());
        }
    }

    private static void errorResponse(HttpServletRequest request, HttpServletResponse response, Exception e, String errorCode) throws IOException {
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_BAD_REQUEST); // 400 error

        final Map<String, Object> body = new HashMap<>();
        body.put("errorCode ", errorCode);
        body.put("date", new Date());
        body.put("message", e.getMessage());
        body.put("request", request.getRequestURI());

        final ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(response.getOutputStream(), body);
    }


}
