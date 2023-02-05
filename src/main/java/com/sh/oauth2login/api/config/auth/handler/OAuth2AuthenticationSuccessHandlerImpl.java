package com.sh.oauth2login.api.config.auth.handler;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Provider;
import java.util.Map;

@Slf4j
@Component
public class OAuth2AuthenticationSuccessHandlerImpl implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {


//        System.out.println("========= " + authentication.getPrincipal() + " =============");
//        System.out.println("========= " + authentication.getDetails() + " =============");
//        System.out.println("========= " + authentication.getCredentials() + " =============");
//        System.out.println("========= " + authentication.getName() + " =============");

        String[] path = request.getRequestURI().split("/");

//        for (String pathes : path) {
//            System.out.println("================= path = " + pathes + " ===================");
//        }

        log.info("=========== " + path[path.length-1] + " 소셜 로그인 성공" + " ===============");

        String uri = UriComponentsBuilder.fromUriString( "http://localhost:9999/api/auth/login-success")
                .queryParam("provider", path[path.length-1])
                .build().toUriString();

        response.sendRedirect(uri);


    }
}
