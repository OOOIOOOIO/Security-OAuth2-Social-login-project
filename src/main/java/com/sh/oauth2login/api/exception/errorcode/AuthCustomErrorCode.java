package com.sh.oauth2login.api.exception.errorcode;

public enum AuthCustomErrorCode {
    // security
    UsernameNotFoundException("A001"),
    UnauthorizedException("A002"),

    // jwt
    RefreshTokenExpiredException("J001"),
    UnsupportedJwtException("J002"),
    MalformedJwtException("J003"),
    SignatureException("J004"),
    JwtTokenExpiredException("J005"),
    RefreshTokenNotFoundException("J006");







    private String errorCode;

    AuthCustomErrorCode(String errorCode) {
        this.errorCode = errorCode;
    }
    public String code(){
        return errorCode;
    }
}
