package com.egs.pyruz;

import com.egs.pyruz.models.entity.Role;
import com.egs.pyruz.models.entity.User;
import com.egs.pyruz.models.enums.ERole;
import com.egs.pyruz.repository.RoleRepository;
import com.egs.pyruz.service.UserService;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@Component
public class Initializer implements ApplicationRunner {

    final UserService userService;
    final RoleRepository roleRepository;
    final PasswordEncoder encoder;

    public Initializer(UserService userService, RoleRepository roleRepository, PasswordEncoder encoder) {
        this.userService = userService;
        this.roleRepository = roleRepository;
        this.encoder = encoder;
    }

    public void run(ApplicationArguments applicationArguments) {
        if (!userService.existsByUsername("admin")) {
            User user = new User(
                    "Pyruz",
                    "Janbaaz",
                    "admin",
                    "admin@admin.com",
                    encoder.encode("admin")
            );


            Set<Role> roles = new HashSet<>();
            List<Role> roleList = roleRepository.findAll();
            if (!roleList.isEmpty()) {
                Role userRole = roleList.stream().filter(r -> r.getName().equals(ERole.ROLE_USER)).findFirst().get();
                roles.add(userRole);
                Role adminRole = roleList.stream().filter(r -> r.getName().equals(ERole.ROLE_ADMIN)).findFirst().get();
                roles.add(adminRole);
            }
            user.setRoles(roles);
            userService.newUser(user);
        }
    }
}
