package com.sh.oauth2login.api.controller.dto.request;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class OAuthLoginInfoDto {

    private String email;
    private String provider;
}
