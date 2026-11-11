package com.yashsomani.secure_file_transfer;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DecryptController {

    @PostMapping("/api/decrypt")
    public ResponseEntity<String> decryptFile() {

        return ResponseEntity.status(410)
                .body("This endpoint is deprecated. Use secure file download.");
    }
}
