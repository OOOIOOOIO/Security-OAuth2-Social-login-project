package com.sh.oauth2login.api.config.auth;

import com.sh.oauth2login.api.domain.User;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

@Getter
public class UserDetailsImpl implements UserDetails {

    private static final Long serialVersionUID = 1L;

    private Long userId;
    private String email;
    private String provider;
    private Collection<? extends GrantedAuthority> authorities;

    public UserDetailsImpl(Long userId, String email, String provider, Collection<? extends GrantedAuthority> authorities) {
        this.userId = userId;
        this.email = email;
        this.provider = provider;
        this.authorities = authorities;
    }

    public static UserDetailsImpl build(User user) {
        List<GrantedAuthority> authorities = Arrays.stream(new String[]{user.getRoleKey()})
                .map(role -> new SimpleGrantedAuthority(role))
                .collect(Collectors.toList());

        return new UserDetailsImpl(
                user.getUserId(),
                user.getEmail(),
                user.getProvider(),
                authorities);
    }


    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public String getUsername() {
        return null;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }

        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }

        UserDetailsImpl user = (UserDetailsImpl) obj;
        return Objects.equals(userId, user.userId);
    }
}