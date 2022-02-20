package com.egs.pyruz.service;

import com.egs.pyruz.configuration.ApplicationProperties;
import com.egs.pyruz.models.dto.MessageDTO;
import com.egs.pyruz.models.dto.ServiceExceptionDTO;
import com.egs.pyruz.models.dto.TokenRefreshDTO;
import com.egs.pyruz.models.entity.RefreshToken;
import com.egs.pyruz.repository.RefreshTokenRepository;
import com.egs.pyruz.repository.UserRepository;
import com.egs.pyruz.security.JwtUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.UUID;

@Service
public class RefreshTokenService extends BaseService {

    @Value("${application.jwt.refresh.expiration.duration}")
    private Long refreshTokenDurationMs;

    final RefreshTokenRepository refreshTokenRepository;

    public RefreshTokenService(JwtUtils jwtUtils, UserRepository userRepository, ApplicationProperties applicationProperties, RefreshTokenRepository refreshTokenRepository) {
        super(jwtUtils, userRepository, applicationProperties);
        this.refreshTokenRepository = refreshTokenRepository;
    }

    public TokenRefreshDTO findByToken(String token) {
        return refreshTokenRepository.findByToken(token)
                .map(this::verifyExpiration)
                .map(RefreshToken::getUser)
                .map(user -> {
                    String newToken = jwtUtils.generateTokenFromUsername(user.getUsername());
                    return new TokenRefreshDTO(newToken, token);
                })
                .orElseThrow(
                        () -> new ServiceExceptionDTO(
                                applicationProperties.getProperty("application.message.refresh.token.not.exist"),
                                HttpStatus.NOT_ACCEPTABLE
                        )
                );
    }

    public RefreshToken createRefreshToken(Long userId) {
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(userRepository.findById(userId).orElseThrow(
                () -> new ServiceExceptionDTO(
                        applicationProperties.getProperty("application.message.user.dose.not.exist"),
                        HttpStatus.NOT_FOUND
                )
        ));
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
        refreshToken.setToken(UUID.randomUUID().toString());
        refreshToken = refreshTokenRepository.save(refreshToken);
        return refreshToken;
    }

    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token);
            throw new ServiceExceptionDTO(
                    applicationProperties.getProperty("application.message.refresh.token.expired"),
                    HttpStatus.NOT_ACCEPTABLE
            );
        }
        return token;
    }

    @Transactional
    public MessageDTO deleteByUser(HttpServletRequest request) {
        refreshTokenRepository.deleteByUser(getUserEntity(request));
        return new MessageDTO(applicationProperties.getProperty("application.message.successfully.logout"));
    }
}
