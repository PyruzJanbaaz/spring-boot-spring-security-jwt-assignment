package com.egs.pyruz.controllers;

import com.egs.pyruz.models.domain.LoginRequest;
import com.egs.pyruz.models.domain.RegisterUserRequest;
import com.egs.pyruz.models.domain.UserChangePasswordRequest;
import com.egs.pyruz.models.domain.UserUpdateRequest;
import com.egs.pyruz.models.dto.MessageDTO;
import com.egs.pyruz.service.UserService;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api")
public class UserController {

    final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/v1/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        return new ResponseEntity(userService.authenticateUser(loginRequest), HttpStatus.OK);
    }

    @PostMapping("/v1/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterUserRequest registerUserRequest) {
        return new ResponseEntity(userService.registerUser(registerUserRequest), HttpStatus.CREATED);
    }

    @GetMapping("/v1/users")
    public ResponseEntity<?> getAllUsers() {
        return new ResponseEntity<>(userService.getAllUsers(), HttpStatus.OK);
    }

    @GetMapping("/v1/user/findById")
    public ResponseEntity<?> getUserById(@RequestParam Long id) {
        return new ResponseEntity<>(userService.getUserById(id), HttpStatus.OK);
    }

    @DeleteMapping("/v1/user")
    @PreAuthorize("hasRole('ADMIN')")
    public MessageDTO deleteUser(@RequestParam Long id) {
        return userService.deleteUser(id);
    }

    @PutMapping("/v1/user")
    @PreAuthorize("hasRole('ADMIN')")
    public MessageDTO user(@Valid @RequestBody UserUpdateRequest userUpdateRequest) {
        return userService.updateUser(userUpdateRequest);
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('USER')")
    public String userAccess() {
        return "This is a secured page and just will loaded for USER role!";
    }

    @PutMapping("/v1/user/changePassword")
    @PreAuthorize("hasRole('USER')")
    public MessageDTO user(@Valid @RequestBody UserChangePasswordRequest userChangePasswordRequest, HttpServletRequest request) {
        return userService.changePassword(userChangePasswordRequest, request);
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminAccess() {
        return "This is a secured page and just will loaded for ADMIN role!";
    }
}
