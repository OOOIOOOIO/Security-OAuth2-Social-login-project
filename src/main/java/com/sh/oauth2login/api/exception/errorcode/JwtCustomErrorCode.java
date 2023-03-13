package com.sh.oauth2login.api.exception.errorcode;

public enum JwtCustomErrorCode {
    // security
    UsernameNotFoundException("S001"),
    UnauthorizedException("S002"),

    // jwt
    TokenRefreshException("J001"),
    UnsupportedJwtException("J002"),
    MalformedJwtException("J003"),
    SignatureException("J004"),
    JwtTokenExpiredException("J005"),
    TokenNotFoundException("J006"),
    IllegalArgumentException("C001");





    private String errorCode;

    JwtCustomErrorCode(String errorCode) {
        this.errorCode = errorCode;
    }
    public String code(){
        return errorCode;
    }
}
