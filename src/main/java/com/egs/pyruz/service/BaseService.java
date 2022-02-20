package com.egs.pyruz.service;

import com.egs.pyruz.configuration.ApplicationProperties;
import com.egs.pyruz.models.dto.ServiceExceptionDTO;
import com.egs.pyruz.models.entity.User;
import com.egs.pyruz.repository.UserRepository;
import com.egs.pyruz.security.JwtUtils;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;

@Service
public class BaseService {

    final JwtUtils jwtUtils;
    final UserRepository userRepository;
    final ApplicationProperties applicationProperties;

    public BaseService(JwtUtils jwtUtils, UserRepository userRepository, ApplicationProperties applicationProperties) {
        this.jwtUtils = jwtUtils;
        this.userRepository = userRepository;
        this.applicationProperties = applicationProperties;
    }

    protected User getUserEntity(HttpServletRequest request) {
        String username = jwtUtils.getUserNameFromJwtToken(jwtUtils.parseJwt(request));
        return getCurrentUserByUsername(username);
    }

    protected User getCurrentUserById(Long id) {
        return userRepository.findById(id).orElseThrow(
                () -> new ServiceExceptionDTO(
                        applicationProperties.getProperty("application.message.user.dose.not.exist"),
                        HttpStatus.NOT_FOUND
                )
        );
    }

    protected User getCurrentUserByUsername(String username) {
        return userRepository.findByUsername(username).orElseThrow(
                () -> new ServiceExceptionDTO(
                        applicationProperties.getProperty("application.message.user.dose.not.exist"),
                        HttpStatus.NOT_FOUND
                )
        );
    }

}
