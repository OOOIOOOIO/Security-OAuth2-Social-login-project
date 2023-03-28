package com.sh.oauth2login.api.exception.controlleradvice;

import com.sh.oauth2login.api.exception.ErrorMessage;
import com.sh.oauth2login.api.exception.errorcode.AuthCustomErrorCode;
import com.sh.oauth2login.api.exception.errorcode.GlobalCustomErrorCode;
import com.sh.oauth2login.api.exception.type.UserNotFoundException;
import com.sh.oauth2login.api.exception.type.RefreshTokenNotFoundException;
import com.sh.oauth2login.api.exception.type.RefreshTokenExpiredException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.server.MethodNotAllowedException;

import java.util.Date;

/**
 * 리프레쉬 토큰 에러
 * TokenRefreshException : 403
 *
 */

@Slf4j
@RestControllerAdvice
public class TokenControllerAdvice {

    /**
     * RefreshTokenExpiredException : 403
     */

    @ExceptionHandler(value = RefreshTokenExpiredException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN) // 403 error
    public ErrorMessage handleTokenRefreshException(RefreshTokenExpiredException ex, WebRequest request) {

        log.error(ex.getMessage());

        return new ErrorMessage(
                AuthCustomErrorCode.RefreshTokenExpiredException.code(),
                new Date(),
                ex.getMessage(),
                request.getDescription(false)
        );
    }

    @ExceptionHandler(value = RefreshTokenNotFoundException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST) // 400 error
    public ErrorMessage handleTokenNotFoundException(RefreshTokenNotFoundException ex, WebRequest request) {

        log.error(ex.getMessage());

        return new ErrorMessage(
                AuthCustomErrorCode.RefreshTokenNotFoundException.code(),
                new Date(),
                ex.getMessage(),
                request.getDescription(false)
        );
    }

    /**
     * Client Error
     */

    @ExceptionHandler(value = MethodNotAllowedException.class)
    @ResponseStatus(HttpStatus.METHOD_NOT_ALLOWED) // 405 error
    public ErrorMessage handleMethodNotAllowedException(MethodNotAllowedException ex, WebRequest request) {

        log.error(ex.getMessage());

        return new ErrorMessage(
                GlobalCustomErrorCode.MethodNotAllowedException.code(),
                new Date(),
                ex.getMessage(),
                request.getDescription(false)
        );
    }

    @ExceptionHandler(value = IllegalArgumentException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST) // 400 error
    public ErrorMessage handleIllegalArgumentException(IllegalArgumentException ex, WebRequest request) {

        log.error(ex.getMessage());

        return new ErrorMessage(
                GlobalCustomErrorCode.IllegalArgumentException.code(),
                new Date(),
                ex.getMessage(),
                request.getDescription(false)
        );
    }


    @ExceptionHandler(value = UserNotFoundException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR) // 500 error
    public ErrorMessage handleUserNotFoundException(UserNotFoundException ex, WebRequest request) {

        log.error(ex.getMessage());

        return new ErrorMessage(
                GlobalCustomErrorCode.UserNotFoundException.code(),
                new Date(),
                ex.getMessage(),
                request.getDescription(false)
        );
    }


    @ExceptionHandler(value = IllegalStateException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR) // 500 error
    public ErrorMessage handleIllegalStateException(IllegalStateException ex, WebRequest request) {

        log.error(ex.getMessage());

        return new ErrorMessage(
                GlobalCustomErrorCode.IllegalStateException.code(),
                new Date(),
                ex.getMessage(),
                request.getDescription(false)
        );
    }




}



