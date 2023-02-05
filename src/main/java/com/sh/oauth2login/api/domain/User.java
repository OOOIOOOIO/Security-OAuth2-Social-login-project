package com.sh.oauth2login.api.domain;

import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Table(name = "USERS")
public class User extends BaseEntity{
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    private Long userId;

    @Column(name = "user_name")
    private String name;
    @Column(name = "user_email")
    private String email;

    private String picture;

    @Enumerated(EnumType.STRING)
    @Column(name = "user_role")
    private Role role;


    private String provider; //Auth 종류(google, naver 등)
//    private String provideId; // 해당 OAuth 의 key(id)


    @Builder
    public User(String name, String email, String picture, Role role, String provider) {
        this.name = name;
        this.email = email;
        this.picture = picture;
        this.role = role;
        this.provider = provider;


    }

    public User update(String name, String email, String picture, String provider) {
        this.name = name;
        this.email = email;
        this.picture = picture;
        this.provider = provider;

        return this;
    }
    public String getRoleKey(){
        return this.role.getKey();
    }




}