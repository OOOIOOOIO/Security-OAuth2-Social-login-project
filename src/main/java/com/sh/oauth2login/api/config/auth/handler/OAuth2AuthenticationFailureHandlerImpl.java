package com.sh.oauth2login.api.config.auth.handler;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@Component
public class OAuth2AuthenticationFailureHandlerImpl implements AuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        log.info("=========== " + "소셜 로그인 성공" + " ===============");

        String[] path = request.getRequestURI().split("/");


        for (String pathes : path) {
            System.out.println("================= path = " + pathes + " ===================");
        }
//        Provider provider = Provider.valueOf(path[path.length - 1].toUpperCase());


        String uri = UriComponentsBuilder.fromUriString( "http://localhost:9999/api/auth/loginFaile")
//                .queryParam("provider", provider)
//                .queryParam("oauthId", oauthId)
                .build().toUriString();

        response.sendRedirect(uri);

    }
}
