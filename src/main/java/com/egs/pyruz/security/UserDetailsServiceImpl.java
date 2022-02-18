package com.egs.pyruz.security;

import com.egs.pyruz.configuration.ApplicationProperties;
import com.egs.pyruz.models.dto.ServiceExceptionDTO;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.egs.pyruz.models.entity.User;
import com.egs.pyruz.repository.UserRepository;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    final UserRepository userRepository;
    final ApplicationProperties applicationProperties;

    public UserDetailsServiceImpl(UserRepository userRepository, ApplicationProperties applicationProperties) {
        this.userRepository = userRepository;
        this.applicationProperties = applicationProperties;
    }

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username).orElseThrow(
                () -> new ServiceExceptionDTO(
                        applicationProperties.getProperty("application.message.data.not.found") + username,
                        HttpStatus.NOT_FOUND
                )
        );
        return UserDetailsImpl.build(user);
    }

}
