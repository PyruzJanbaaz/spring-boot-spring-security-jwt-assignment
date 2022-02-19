package com.egs.pyruz.service;

import com.egs.pyruz.configuration.ApplicationProperties;
import com.egs.pyruz.models.domain.LoginRequest;
import com.egs.pyruz.models.domain.RegisterUserRequest;
import com.egs.pyruz.models.domain.UserChangePasswordRequest;
import com.egs.pyruz.models.domain.UserUpdateRequest;
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
import org.hibernate.service.spi.ServiceException;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.util.*;
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
                encoder.encode(registerUserRequest.getPassword()),
                UUID.randomUUID().toString()
        );

        Set<String> inputRoles = registerUserRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (inputRoles == null || inputRoles.isEmpty()) {
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

    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    public User getUserById(Long id) {
        return getCurrentUserById(id);
    }

    public MessageDTO deleteUser(Long id) {
        User user = getCurrentUserById(id);
        userRepository.delete(user);
        return new MessageDTO(applicationProperties.getProperty("application.message.user.deleted.successfully"));
    }

    public MessageDTO updateUser(UserUpdateRequest userUpdateRequest) {
        User user = getCurrentUserById(userUpdateRequest.getId());
        user.setFirstName(userUpdateRequest.getFirstName());
        user.setLastName(userUpdateRequest.getLastName());
        userRepository.save(user);
        return new MessageDTO(applicationProperties.getProperty("application.message.user.updated.successfully"));
    }

    public MessageDTO changePassword(UserChangePasswordRequest userChangePasswordRequest, HttpServletRequest request) {
        User user = getUserEntity(request);
        if (!encoder.matches(userChangePasswordRequest.getOldPassword(), user.getPassword())) {
            throw new ServiceExceptionDTO(
                    applicationProperties.getProperty("application.message.incorrect.password"),
                    HttpStatus.BAD_REQUEST
            );
        } else if (!userChangePasswordRequest.getPassword().equals(userChangePasswordRequest.getConfirmPassword())) {
            throw new ServiceExceptionDTO(
                    applicationProperties.getProperty("application.message.password.not.matched"),
                    HttpStatus.BAD_REQUEST
            );
        } else {
            user.setPassword(encoder.encode(userChangePasswordRequest.getPassword()));
            userRepository.save(user);
            return new MessageDTO(applicationProperties.getProperty("application.message.password.changed.successfully"));
        }
    }

    private User getUserEntity(HttpServletRequest request) {
        String username = jwtUtils.getUserNameFromJwtToken(jwtUtils.parseJwt(request));
        return getCurrentUserByUsername(username);
    }

    private User getCurrentUserById(Long id) {
        return userRepository.findById(id).orElseThrow(
                () -> new ServiceExceptionDTO(
                        applicationProperties.getProperty("application.message.user.dose.not.exist"),
                        HttpStatus.NOT_FOUND
                )
        );
    }

    private User getCurrentUserByUsername(String username) {
        return userRepository.findByUsername(username).orElseThrow(
                () -> new ServiceExceptionDTO(
                        applicationProperties.getProperty("application.message.user.dose.not.exist"),
                        HttpStatus.NOT_FOUND
                )
        );
    }
}
