
package com.yashsomani.secure_file_transfer;

import com.yashsomani.secure_file_transfer.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class RegisterController {

    private final UserService userService;

    public RegisterController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(
            @RequestParam String username,
            @RequestParam String email,
            @RequestParam String password) {

        try {
            User user = userService.registerUser(
                    username, email, password
            );

            return ResponseEntity.status(HttpStatus.CREATED)
                    .body("Registration successful! User ID: "
                            + user.getId());

        } catch (IllegalArgumentException e) {

            return ResponseEntity.badRequest()
                    .body(e.getMessage());
        }
    }
}
