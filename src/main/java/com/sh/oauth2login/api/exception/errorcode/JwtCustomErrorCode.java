package com.sh.oauth2login.api.exception.errorcode;

public enum JwtCustomErrorCode {
    // security
    UsernameNotFoundException("S001"),
    UnauthorizedException("S002"),

    // jwt
    TokenRefreshException("J001"),
    SignatureException("J004"),
    MalformedJwtException("J003"),
    UnsupportedJwtException("J002"),
    JwtTokenExpiredException("J005"),
    IllegalArgumentException("U002");

    private String errorCode;

    JwtCustomErrorCode(String errorCode) {
        this.errorCode = errorCode;
    }
    public String code(){
        return errorCode;
    }
}
