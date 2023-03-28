package com.sh.oauth2login.api.config.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sh.oauth2login.api.exception.errorcode.AuthCustomErrorCode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * 인증 처리 과정에서(비인증 유저일 경우 등) 예외를 던져주는 클래스
 *
 * 401 error 발생
 *
 * ObjectMapper : JSON <==> JAVA 객체 왔다갔다!
 */
@Slf4j
@Component
public class AuthEntryPointJwt implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException{
        log.error("Unauthorized error : {} | request uri : {}", authException.getMessage(), request.getRequestURI());

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // 401 error

        final Map<String, Object> body = new HashMap<>();
        body.put("errorCode", AuthCustomErrorCode.UnauthorizedException.code()); // S002
        body.put("date", new Date());
        body.put("message", authException.getMessage());
        body.put("request", request.getRequestURI());

        final ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(response.getOutputStream(), body);

    }
}
