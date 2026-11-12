package com.yashsomani.secure_file_transfer.controller;

import com.yashsomani.secure_file_transfer.FileMetadata;
import com.yashsomani.secure_file_transfer.service.FileService;
import com.yashsomani.secure_file_transfer.service.FileValidationService;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
public class UploadController {

    private final FileService fileService;
    private final FileValidationService validationService;

    public UploadController(FileService fileService, FileValidationService validationService) {
        this.fileService = fileService;
        this.validationService = validationService;
    }

    @PostMapping("/api/upload")
    public ResponseEntity<String> uploadFile(
            @RequestParam("file") MultipartFile file,
            Authentication authentication) {

        try {
            // Server-side validation
            validationService.validateUpload(file);

            FileMetadata metadata = fileService.uploadFile(
                    file,
                    authentication.getName()
            );

            return ResponseEntity.ok(
                    "File encrypted and saved successfully! " +
                    "Encrypted filename: " +
                    metadata.getEncryptedFilename()
            );

        } catch (FileValidationService.FileValidationException e) {
            return ResponseEntity.badRequest()
                    .body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("File upload failed");
        }
    }
}