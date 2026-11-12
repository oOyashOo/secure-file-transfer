package com.yashsomani.secure_file_transfer.controller;

import com.yashsomani.secure_file_transfer.FileMetadata;
import com.yashsomani.secure_file_transfer.FileEncryptionService;
import com.yashsomani.secure_file_transfer.service.FileService;
import com.yashsomani.secure_file_transfer.service.FileShareService;

import java.nio.charset.StandardCharsets;



import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

import java.io.IOException;


@RestController
@RequestMapping("/api/files")
public class DownloadController {

        private final FileService fileService;
        private final FileEncryptionService encryptionService;
        private final FileShareService fileShareService;

        public DownloadController(
                        FileService fileService,
                        FileEncryptionService encryptionService,
                        FileShareService fileShareService) {

                this.fileService = fileService;
                this.encryptionService = encryptionService;
                this.fileShareService = fileShareService;
        }

        @PostMapping("/{fileId}/download")
        public ResponseEntity<StreamingResponseBody> downloadFile(
                        @PathVariable Long fileId,
                        Authentication authentication) {

                try {
                        // Verify that the file belongs to the logged-in user.
                        FileMetadata metadata = fileService.getOwnedFile(
                                        fileId,
                                        authentication.getName());

                        MediaType contentType = parseContentType(metadata.getContentType());

                        ContentDisposition disposition = ContentDisposition.attachment()
                                        .filename(metadata.getOriginalFilename(), StandardCharsets.UTF_8)
                                        .build();

                        StreamingResponseBody streamingBody = outputStream -> {
                                try {
                                        encryptionService.decryptFileToStream(
                                                metadata.getEncryptedFilename(),
                                                metadata.getKeyVersion(),
                                                outputStream);
                                } catch (Exception e) {
                                        // Log the error without exposing sensitive details
                                        logger.warn("Decryption failed for fileId={}: {}", fileId, e.getMessage());
                                        throw new IOException("Decryption failed", e);
                                }
                        };

                        return ResponseEntity.ok()
                                        .contentType(contentType)
                                        .header(HttpHeaders.CONTENT_DISPOSITION, disposition.toString())
                                        .body(streamingBody);

                } catch (IllegalArgumentException e) {
                        return ResponseEntity.notFound().build();
                } catch (Exception e) {
                        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
                }
        }

        @PostMapping("/shares/{shareId}/download")
        public ResponseEntity<StreamingResponseBody> downloadSharedFile(
                        @PathVariable Long shareId,
                        Authentication authentication) {

                try {
                        FileMetadata metadata = fileShareService.getSharedFile(
                                        shareId,
                                        authentication.getName());

                        MediaType contentType = parseContentType(metadata.getContentType());

                        ContentDisposition disposition = ContentDisposition.attachment()
                                        .filename(metadata.getOriginalFilename(), StandardCharsets.UTF_8)
                                        .build();

                        StreamingResponseBody streamingBody = outputStream -> {
                                try {
                                        encryptionService.decryptFileToStream(
                                                metadata.getEncryptedFilename(),
                                                metadata.getKeyVersion(),
                                                outputStream);
                                } catch (Exception e) {
                                        logger.warn("Decryption failed for shareId={}: {}", shareId, e.getMessage());
                                        throw new IOException("Decryption failed", e);
                                }
                        };

                        return ResponseEntity.ok()
                                        .contentType(contentType)
                                        .header(HttpHeaders.CONTENT_DISPOSITION, disposition.toString())
                                        .body(streamingBody);

                } catch (IllegalArgumentException e) {
                        return ResponseEntity.notFound().build();
                } catch (Exception e) {
                        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
                }
        }

        private MediaType parseContentType(String contentType) {
                try {
                        return MediaType.parseMediaType(contentType);
                } catch (Exception e) {
                        return MediaType.APPLICATION_OCTET_STREAM;
                }
        }

        private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(DownloadController.class);
}
