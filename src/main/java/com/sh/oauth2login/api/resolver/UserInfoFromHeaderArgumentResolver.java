package com.sh.oauth2login.api.resolver;

import com.sh.oauth2login.api.config.jwt.JwtUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.MethodParameter;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
@Component
public class UserInfoFromHeaderArgumentResolver implements HandlerMethodArgumentResolver {

    private final JwtUtils jwtUtils;


    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.getParameterType().equals(UserInfoFromHeaderDto.class);
    }


    @Override
    public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer, NativeWebRequest webRequest, WebDataBinderFactory binderFactory) throws Exception {

        String jwtFromHeader = jwtUtils.getJwtFromHeader((HttpServletRequest) webRequest.getNativeRequest());
        Map<String, Object> userEmailAndProviderFromJwtToken = jwtUtils.getUserEmailAndProviderFromJwtToken(jwtFromHeader);
        String email = (String)userEmailAndProviderFromJwtToken.get("email");
        String provider = (String)userEmailAndProviderFromJwtToken.get("provider");

        log.info("========== UserInfoFromHeaderArgumentResolver ==========");
        log.info("========== Get email : " + email + " | provider : " + provider + "==========");

        return new UserInfoFromHeaderDto(email, provider);
    }
}
