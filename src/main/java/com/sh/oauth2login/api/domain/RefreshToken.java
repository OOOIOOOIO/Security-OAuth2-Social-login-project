package com.sh.oauth2login.api.domain;

import lombok.*;

import javax.persistence.*;
import java.time.Instant;

@Getter
@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Table(name = "REFRESH_TOKEN")
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "refresh_id")
    private Long refreshId;

    private String token;

    @Column(name = "expiry_date")
    private Instant expiryDate;

    @OneToOne
    @JoinColumn(name = "user_id")
    private User user;

    @Builder
    public RefreshToken(String token, Instant expiryDate, User user) {
        this.token = token;
        this.expiryDate = expiryDate;
        this.user = user;
    }
}
