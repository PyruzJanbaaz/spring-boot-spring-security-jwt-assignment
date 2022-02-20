package com.egs.pyruz.repository;

import com.egs.pyruz.models.entity.RefreshToken;
import com.egs.pyruz.models.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);
    @Modifying
    Integer deleteByUser(User user);
}
