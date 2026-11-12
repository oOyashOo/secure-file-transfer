package com.yashsomani.secure_file_transfer.controller;

import com.yashsomani.secure_file_transfer.User;
import com.yashsomani.secure_file_transfer.dto.RegistrationRequest;
import com.yashsomani.secure_file_transfer.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/auth")
@Validated
public class RegisterController {

    private final UserService userService;

    public RegisterController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@Valid @RequestBody RegistrationRequest request) {
        try {
            User user = userService.registerUser(
                    request.getUsername(), request.getEmail(), request.getPassword()
            );

            return ResponseEntity.status(HttpStatus.CREATED)
                    .body("Registration successful! User ID: " + user.getId());

        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
}