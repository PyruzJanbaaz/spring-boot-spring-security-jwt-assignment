package com.egs.pyruz.service;

import com.egs.pyruz.configuration.ApplicationProperties;
import com.egs.pyruz.models.domain.LoginRequest;
import com.egs.pyruz.models.domain.RegisterUserRequest;
import com.egs.pyruz.models.dto.JwtDTO;
import com.egs.pyruz.models.dto.MessageDTO;
import com.egs.pyruz.models.dto.ServiceExceptionDTO;
import com.egs.pyruz.models.entity.Role;
import com.egs.pyruz.models.entity.User;
import com.egs.pyruz.models.enums.ERole;
import com.egs.pyruz.repository.RoleRepository;
import com.egs.pyruz.repository.UserRepository;
import com.egs.pyruz.security.JwtUtils;
import com.egs.pyruz.security.UserDetailsImpl;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class UserService {

    final ApplicationProperties applicationProperties;
    final AuthenticationManager authenticationManager;
    final UserRepository userRepository;
    final RoleRepository roleRepository;
    final PasswordEncoder encoder;
    final JwtUtils jwtUtils;

    public UserService(ApplicationProperties applicationProperties, AuthenticationManager authenticationManager, UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder encoder, JwtUtils jwtUtils) {
        this.applicationProperties = applicationProperties;
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.encoder = encoder;
        this.jwtUtils = jwtUtils;
    }


    public JwtDTO authenticateUser(LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
        return new JwtDTO(jwt,
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles);
    }

    public MessageDTO registerUser(RegisterUserRequest registerUserRequest) {
        if (userRepository.existsByUsername(registerUserRequest.getUsername())) {
            throw new ServiceExceptionDTO(
                    applicationProperties.getProperty("application.message.username.is.already.taken"),
                    HttpStatus.BAD_REQUEST
            );
        }
        if (userRepository.existsByEmail(registerUserRequest.getEmail())) {
            throw new ServiceExceptionDTO(
                    applicationProperties.getProperty("application.message.email.is.already.use"),
                    HttpStatus.BAD_REQUEST
            );
        }

        // Create new user's account
        User user = new User(
                registerUserRequest.getUsername(),
                registerUserRequest.getEmail(),
                encoder.encode(registerUserRequest.getPassword())
        );

        Set<String> inputRoles = registerUserRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (inputRoles.isEmpty()) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER).orElseThrow(
                    () -> new ServiceExceptionDTO(
                            applicationProperties.getProperty("application.message.role.dose.not.exist"),
                            HttpStatus.NOT_FOUND
                    )
            );
            roles.add(userRole);
        } else {
            inputRoles.forEach(role -> {
                if (applicationProperties.getProperty("application.property.admin").equals(role)) {
                    Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN).orElseThrow(
                            () -> new ServiceExceptionDTO(
                                    applicationProperties.getProperty("application.message.role.dose.not.exist"),
                                    HttpStatus.NOT_FOUND
                            )
                    );
                    roles.add(adminRole);
                } else {
                    Role userRole = roleRepository.findByName(ERole.ROLE_USER).orElseThrow(
                            () -> new ServiceExceptionDTO(
                                    applicationProperties.getProperty("application.message.role.dose.not.exist"),
                                    HttpStatus.NOT_FOUND
                            )
                    );
                    roles.add(userRole);
                }
            });
        }
        user.setRoles(roles);
        userRepository.save(user);
        return new MessageDTO(applicationProperties.getProperty("application.message.user.registered.successfully"));
    }

}
