package com.sh.oauth2login.api.config.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sh.oauth2login.api.exception.errorcode.JwtCustomErrorCode;
import com.sh.oauth2login.api.exception.type.JwtTokenExpiredException;
import io.jsonwebtoken.security.SignatureException;
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
public class JwtExceptionHandlerFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)  throws ServletException, IOException {

        try {
            filterChain.doFilter(request, response);
        } catch (SignatureException e) {
            errorResponse(request, response, e, JwtCustomErrorCode.SignatureException.code());
        } catch (MalformedJwtException e) {
            errorResponse(request, response, e, JwtCustomErrorCode.MalformedJwtException.code());
        } catch (JwtTokenExpiredException e) {
            errorResponse(request, response, e, JwtCustomErrorCode.JwtTokenExpiredException.code());
        } catch (UnsupportedJwtException e) {
            errorResponse(request, response, e, JwtCustomErrorCode.UnsupportedJwtException.code());
        } catch (IllegalArgumentException e) {
            errorResponse(request, response, e, JwtCustomErrorCode.IllegalArgumentException.code());
        } catch (UsernameNotFoundException e) {
            errorResponse(request, response, e, JwtCustomErrorCode.UsernameNotFoundException.code());
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
