package com.sh.oauth2login.api.config.auth;


import com.sh.oauth2login.api.domain.User;
import com.sh.oauth2login.api.repository.UserRepository;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;



@Getter
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService {

    private final UserRepository userRepository;


    @Transactional
    public UserDetails loadUserByUsernameAndProvider(String email, String provider) throws UsernameNotFoundException {
        User user = userRepository.findByEmailAndProvider(email, provider)
                .orElseThrow(() -> new UsernameNotFoundException("User Not Found with email: " + email));

        return UserDetailsImpl.build(user);
    }

}

/**
 * 이제 social 로그인 후 success, fail시 어떻게 할 지 정하고 구현하면 됌
 */