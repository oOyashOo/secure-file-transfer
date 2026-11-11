package com.yashsomani.secure_file_transfer;

import com.yashsomani.secure_file_transfer.service.FileService;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/files")
public class FileDeleteController {

    private final FileService fileService;

    public FileDeleteController(FileService fileService) {
        this.fileService = fileService;
    }

    @DeleteMapping("/{fileId}")
    public ResponseEntity<?> deleteFile(
        @PathVariable Long fileId,
        Authentication authentication) throws Exception {

        try {
            fileService.deleteMyFile(
                    fileId,
                    authentication.getName()
            );

            return ResponseEntity.ok(
                    "File deleted successfully."
            );

        } catch (IllegalArgumentException e) {
            return ResponseEntity.notFound().build();
        }
    }
}