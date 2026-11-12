package com.yashsomani.secure_file_transfer.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthMeController {

    @GetMapping("/api/auth/me")
    public ResponseEntity<?> getCurrentUser(Authentication authentication) {

        if (authentication == null ||
            !authentication.isAuthenticated()) {
            return ResponseEntity.status(401)
                    .body("Not logged in");
        }

        return ResponseEntity.ok(
                java.util.Map.of(
                        "email", authentication.getName()
                )
        );
    }
}
