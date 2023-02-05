package com.sh.oauth2login.api.config.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class OauthUserDto {
    private String email;
    private String name;
    private String picture;

    @Builder
    public OauthUserDto(String email, String name, String picture) {
        this.email = email;
        this.name = name;
        this.picture = picture;
    }


}
