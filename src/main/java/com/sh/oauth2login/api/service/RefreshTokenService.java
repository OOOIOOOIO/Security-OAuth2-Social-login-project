package com.sh.oauth2login.api.service;

import com.sh.oauth2login.api.domain.RefreshToken;
import com.sh.oauth2login.api.domain.User;
import com.sh.oauth2login.api.exception.type.TokenRefreshException;
import com.sh.oauth2login.api.repository.RefreshTokenRepository;
import com.sh.oauth2login.api.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {
    @Value("${jwt.refreshExpireMin}")
    private Long refreshTokenMin;

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;

    /**
     * 리프레쉬 토큰 토큰 조회
     */
    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

//    /**
//     * 리프레쉬 토큰 userId 조회
//     */
//    public Optional<RefreshToken> findByUserId(Long userId) {
//        return refreshTokenRepository.findByUser_UserId(userId);
//    }

    /**
     * 리프레쉬 토큰 생성 및 저장
     */
    @Transactional
    public RefreshToken createRefreshToken(String email, String provider) {

        User user = userRepository.findByEmailAndProvider(email, provider).orElseThrow(() -> new UsernameNotFoundException("User Not Found with email: " + email));

        RefreshToken refreshToken = RefreshToken.builder()
                .token(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plusMillis(refreshTokenMin))
                .user(user)
                .build();

        // db 저장
        RefreshToken saveRefreshToken = refreshTokenRepository.save(refreshToken);

        return saveRefreshToken;
    }


    /**
     * 만료시간 검증
     */
    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token);
            throw new TokenRefreshException(token.getToken(), "Refresh token was expired. Please make a new signin request");
        }

        return token;
    }


    /**
     * 리프레쉬 토큰 삭제
     */
    @Transactional
    public int deleteByUserId(RefreshToken refreshToken) {


        return refreshTokenRepository.deleteByUser(refreshToken.getUser());
    }


    public Optional<RefreshToken> findByEmailAndProvider(String email, String provider) {
        Optional<User> user = userRepository.findByEmailAndProvider(email, provider);


        return refreshTokenRepository.findByUser_UserId(user.get().getUserId());
    }
}
