package com.sh.oauth2login.api.controller.dto.response.auth;

import com.sh.oauth2login.api.domain.Role;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class UserInfoResponseDto {
    private String accessToken;
    private String refreshToken;
}
