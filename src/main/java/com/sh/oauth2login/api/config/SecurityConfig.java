package com.sh.oauth2login.api.config;

import com.sh.oauth2login.api.config.auth.CustomOAuth2UserService;
import com.sh.oauth2login.api.config.auth.handler.OAuth2AuthenticationFailureHandlerImpl;
import com.sh.oauth2login.api.config.auth.handler.OAuth2AuthenticationSuccessHandlerImpl;
import com.sh.oauth2login.api.config.jwt.AuthEntryPointJwt;
import com.sh.oauth2login.api.config.jwt.AuthTokenFilter;
import com.sh.oauth2login.api.config.jwt.JwtExceptionHandlerFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

//    private final UserDetailsServiceImpl userDetailsService;
    private final AuthEntryPointJwt unauthorizedHandler;
    private final AuthTokenFilter authenticationJwtTokenFilter;
    private final JwtExceptionHandlerFilter jwtExceptionHandlerFilter; // jwt exception handler filter!!

    private final CustomOAuth2UserService customOAuth2UserService;

    private final OAuth2AuthenticationSuccessHandlerImpl oAuth2AuthenticationSuccessHandler;
    private final OAuth2AuthenticationFailureHandlerImpl oAuth2AuthenticationFailureHandler;


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{

        http.cors().and().csrf().disable()
                .exceptionHandling().authenticationEntryPoint(unauthorizedHandler)
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .antMatchers("/", "/favicon.ico", "/error").permitAll() // 소셜로그인 후 uri
                .antMatchers("/api/auth/**","/auth/**", "/login/**", "/test/login").permitAll()// .antMathers().hasRole(권한), RestController
                .antMatchers("/login/**").permitAll() // test Controller
                .anyRequest().authenticated()
                .and()
                .oauth2Login()
                .successHandler(oAuth2AuthenticationSuccessHandler)
                .failureHandler(oAuth2AuthenticationFailureHandler)
                .userInfoEndpoint()
                .userService(customOAuth2UserService); // 실행순서 : userInfoEndpoint().userService -> successHandler()
        


        http.addFilterBefore(authenticationJwtTokenFilter, UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(jwtExceptionHandlerFilter, authenticationJwtTokenFilter.getClass()); // jwt 예외처리 필터

        return http.build();

    }



}
