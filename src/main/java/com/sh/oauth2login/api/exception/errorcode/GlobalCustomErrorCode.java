package com.sh.oauth2login.api.exception.errorcode;

public enum GlobalCustomErrorCode {


    // 클라이언트 error
    IllegalArgumentException("C001"),
    MethodNotAllowedException("C002"),

    // server error,

    UserNotFoundException("S001"),
    IllegalStateException("S002");




    private String errorCode;

    GlobalCustomErrorCode(String errorCode) {
        this.errorCode = errorCode;
    }
    public String code(){
        return errorCode;
    }




}
