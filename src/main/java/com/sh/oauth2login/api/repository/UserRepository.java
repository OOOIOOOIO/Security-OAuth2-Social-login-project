package com.sh.oauth2login.api.repository;

import com.sh.oauth2login.api.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {


    Optional<User> findByEmailAndProvider(String email, String provider);


}
