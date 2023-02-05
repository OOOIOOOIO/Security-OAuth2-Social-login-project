package com.sh.oauth2login.api.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@Getter
@Setter
@AllArgsConstructor
public class ErrorMessage {
    private String errorCode;
    private Date date;
    private String message;
    private String request;
}
