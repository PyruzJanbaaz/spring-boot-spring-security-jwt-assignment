package com.egs.pyruz.controllers;

import com.egs.pyruz.models.domain.*;
import com.egs.pyruz.models.dto.MessageDTO;
import com.egs.pyruz.models.entity.RefreshToken;
import com.egs.pyruz.service.RefreshTokenService;
import com.egs.pyruz.service.UserService;
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
    final RefreshTokenService refreshTokenService;

    public UserController(UserService userService, RefreshTokenService refreshTokenService) {
        this.userService = userService;
        this.refreshTokenService = refreshTokenService;
    }

    @PostMapping("/v1/login")
    public ResponseEntity<?> loginUser(@Valid @RequestBody LoginRequest loginRequest) {
        return new ResponseEntity(userService.authenticateUser(loginRequest), HttpStatus.OK);
    }

    @PostMapping("/v1/logout")
    public ResponseEntity<?> logoutUser(HttpServletRequest request) {
        return new ResponseEntity<>(refreshTokenService.deleteByUser(request), HttpStatus.OK);
    }

    @PostMapping("/v1/refreshToken")
    public ResponseEntity<?> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        return new ResponseEntity<>(refreshTokenService.findByToken(request.getRefreshToken()), HttpStatus.OK);
    }

    @PostMapping("/v1/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterUserRequest registerUserRequest) {
        return new ResponseEntity(userService.registerUser(registerUserRequest), HttpStatus.CREATED);
    }

    @GetMapping("/v1/users")
    public ResponseEntity<?> getAllUsers() {
        return new ResponseEntity<>(userService.getAllUsers(), HttpStatus.OK);
    }

    @GetMapping("/v1/users/page")
    public ResponseEntity<?> getUserByPage(@RequestParam Integer pageNumber, @RequestParam Integer pageSize) {
        return new ResponseEntity<>(userService.getAllUsers(pageNumber, pageSize), HttpStatus.OK);
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
        return "This page is secured & will loaded for USER role!";
    }

    @PutMapping("/v1/user/changePassword")
    @PreAuthorize("hasRole('USER')")
    public MessageDTO user(@Valid @RequestBody UserChangePasswordRequest userChangePasswordRequest, HttpServletRequest request) {
        return userService.changePassword(userChangePasswordRequest, request);
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminAccess() {
        return "This page is secured & will loaded for ADMIN role!";
    }
}
