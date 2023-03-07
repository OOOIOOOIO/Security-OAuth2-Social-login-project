package com.sh.oauth2login.api.exception.type;

public class TokenNotFoundException extends RuntimeException{
    private static final long serialVersionUID = 1L;

    public TokenNotFoundException(String token, String message) {
        super(String.format("Failed for [%s]: %s", token, message));
    }
}
