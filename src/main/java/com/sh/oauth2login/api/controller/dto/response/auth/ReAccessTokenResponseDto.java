package com.sh.oauth2login.api.controller.dto.response.auth;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class ReAccessTokenResponseDto {
    private String message;
    private String accessToken;
}
