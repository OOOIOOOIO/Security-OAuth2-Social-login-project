package com.sh.oauth2login.api.resolver;

import com.gdsc.wero.global.auth.jwt.JwtUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Method;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
@Aspect
public class UserInfoAspect {

    private final JwtUtils jwtUtils;

    // Annotation 포인트컷(적용할 어노테이션)
    @Pointcut("@annotation(com.gdsc.wero.global.resolver.UserInfoFromHeader)")
    public void userInfoFromHeader(){};


    // 포인트컷이 실행될 때 적용될 메서드
    @Before("userInfoFromHeader()")
    public UserInfoFromHeaderDto getUserInfoAOP(){

        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();

        String jwtFromHeader = jwtUtils.getJwtFromHeader(request);
        Map<String, Object> userEmailAndProviderFromJwtToken = jwtUtils.getUserEmailAndProviderFromJwtToken(jwtFromHeader);
        String email = (String)userEmailAndProviderFromJwtToken.get("email");
        String provider = (String)userEmailAndProviderFromJwtToken.get("provider");

        log.info("%%%%%%%%%%%%%%%%%%% : " + email);
        log.info("%%%%%%%%%%%%%%%%%%% : " + provider);


        return new UserInfoFromHeaderDto(email, provider);


    }


    // JoinPoint로 메서드 정보 가져오기
    private Method getMethod(JoinPoint joinPoint) {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();



        return signature.getMethod();
    }
}
