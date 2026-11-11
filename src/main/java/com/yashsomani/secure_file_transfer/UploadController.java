package com.yashsomani.secure_file_transfer;

import com.yashsomani.secure_file_transfer.service.FileService;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
public class UploadController {

    private final FileService fileService;

    public UploadController(FileService fileService) {
        this.fileService = fileService;
    }

    @PostMapping("/api/upload")
    public ResponseEntity<String> uploadFile(
            @RequestParam("file") MultipartFile file,
            Authentication authentication) {

        try {
            if (file.isEmpty()) {
                return ResponseEntity.badRequest()
                        .body("Please select a file.");
            }

            FileMetadata metadata = fileService.uploadFile(
                    file,
                    authentication.getName()
            );

            return ResponseEntity.ok(
                    "File encrypted and saved successfully! " +
                    "Encrypted filename: " +
                    metadata.getEncryptedFilename()
            );

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("File upload failed: " + e.getMessage());
        }
    }
}