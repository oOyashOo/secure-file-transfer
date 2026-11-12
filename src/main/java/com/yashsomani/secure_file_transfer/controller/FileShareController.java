package com.yashsomani.secure_file_transfer.controller;

import com.yashsomani.secure_file_transfer.dto.FileShareResponse;
import com.yashsomani.secure_file_transfer.service.FileShareService;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/shares")
public class FileShareController {

    private final FileShareService fileShareService;

    public FileShareController(FileShareService fileShareService) {
        this.fileShareService = fileShareService;
    }

    // Share a file with another user
    @PostMapping("/{fileId}")
    public ResponseEntity<FileShareResponse> shareFile(
            @PathVariable Long fileId,
            @RequestParam String recipientEmail,
            Authentication authentication) {

        return ResponseEntity.ok(
                fileShareService.shareFile(
                        fileId,
                        recipientEmail,
                        authentication.getName()
                )
        );
    }

    // Files shared with the logged-in user
    @GetMapping("/received")
    public ResponseEntity<List<FileShareResponse>> getSharedWithMe(
            Authentication authentication) {

        return ResponseEntity.ok(
                fileShareService.getSharedWithMe(authentication.getName())
        );
    }

    // Files shared by the logged-in user
    @GetMapping("/sent")
    public ResponseEntity<List<FileShareResponse>> getSharedByMe(
            Authentication authentication) {

        return ResponseEntity.ok(
                fileShareService.getSharedByMe(authentication.getName())
        );
    }

    // Revoke a shared file
    @DeleteMapping("/{shareId}")
    public ResponseEntity<String> revokeShare(
            @PathVariable Long shareId,
            Authentication authentication) {

        fileShareService.revokeShare(shareId, authentication.getName());

        return ResponseEntity.ok("File sharing revoked successfully.");
    }
}