package com.yashsomani.secure_file_transfer;

import com.yashsomani.secure_file_transfer.service.FileService;
import com.yashsomani.secure_file_transfer.service.FileShareService;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.HexFormat;

@RestController
@RequestMapping("/api/files")
public class DownloadController {

        private final FileService fileService;
        private final FileEncryptionService encryptionService;
        private final FileShareService fileShareService;

        private final Path decryptedDirectory = Paths.get("decrypted-uploads")
                        .toAbsolutePath()
                        .normalize();

        public DownloadController(
                        FileService fileService,
                        FileEncryptionService encryptionService,
                        FileShareService fileShareService) {

                this.fileService = fileService;
                this.encryptionService = encryptionService;
                this.fileShareService = fileShareService;
        }

        @PostMapping("/{fileId}/download")
        public ResponseEntity<Resource> downloadFile(
                        @PathVariable Long fileId,
                        Authentication authentication) {

                try {
                        // Verify that the file belongs to the logged-in user.
                        FileMetadata metadata = fileService.getOwnedFile(
                                        fileId,
                                        authentication.getName());

                        // Decrypt the authorized file.
                        String decryptedFilename = encryptionService.decryptFile(
                                        metadata.getEncryptedFilename(),
                                        metadata.getKeyVersion());

                        String safeFilename = Paths.get(decryptedFilename)
                                        .getFileName()
                                        .toString();

                        Path filePath = decryptedDirectory.resolve(safeFilename).normalize();

                        if (!filePath.startsWith(decryptedDirectory)
                                        || !Files.isRegularFile(filePath)) {

                                return ResponseEntity.notFound().build();
                        }
                        // Verify SHA-256 integrity before sending the file
                        if (!verifySha256(filePath, metadata.getSha256Hash())) {

                                Files.deleteIfExists(filePath);

                                return ResponseEntity.status(422).build();
                        }

                        Resource resource = new UrlResource(filePath.toUri());

                        if (!resource.exists() || !resource.isReadable()) {
                                return ResponseEntity.notFound().build();
                        }

                        MediaType contentType;

                        try {
                                contentType = MediaType.parseMediaType(
                                                metadata.getContentType());
                        } catch (Exception e) {
                                contentType = MediaType.APPLICATION_OCTET_STREAM;
                        }

                        ContentDisposition disposition = ContentDisposition.attachment()
                                        .filename(
                                                        metadata.getOriginalFilename(),
                                                        StandardCharsets.UTF_8)
                                        .build();

                        return ResponseEntity.ok()
                                        .contentType(contentType)
                                        .header(
                                                        HttpHeaders.CONTENT_DISPOSITION,
                                                        disposition.toString())
                                        .body(resource);

                } catch (IllegalArgumentException e) {
                        return ResponseEntity.notFound().build();

                } catch (Exception e) {
                        return ResponseEntity
                                        .status(HttpStatus.INTERNAL_SERVER_ERROR)
                                        .build();
                }
        }

        @PostMapping("/shares/{shareId}/download")
        public ResponseEntity<Resource> downloadSharedFile(
                        @PathVariable Long shareId,
                        Authentication authentication) {

                try {
                        FileMetadata metadata = fileShareService.getSharedFile(
                                        shareId,
                                        authentication.getName());

                        String decryptedFilename = encryptionService.decryptFile(
                                        metadata.getEncryptedFilename(),
                                        metadata.getKeyVersion());

                        String safeFilename = Paths.get(decryptedFilename)
                                        .getFileName()
                                        .toString();

                        Path filePath = decryptedDirectory.resolve(safeFilename).normalize();

                        if (!filePath.startsWith(decryptedDirectory)
                                        || !Files.isRegularFile(filePath)) {
                                return ResponseEntity.notFound().build();
                        }
                        // Verify SHA-256 integrity before sending the file
                        if (!verifySha256(filePath, metadata.getSha256Hash())) {

                                Files.deleteIfExists(filePath);

                                return ResponseEntity.status(422).build();
                        }

                        Resource resource = new UrlResource(filePath.toUri());

                        if (!resource.exists() || !resource.isReadable()) {
                                return ResponseEntity.notFound().build();
                        }

                        MediaType contentType;

                        try {
                                contentType = MediaType.parseMediaType(metadata.getContentType());
                        } catch (Exception e) {
                                contentType = MediaType.APPLICATION_OCTET_STREAM;
                        }

                        ContentDisposition disposition = ContentDisposition.attachment()
                                        .filename(metadata.getOriginalFilename(), StandardCharsets.UTF_8)
                                        .build();

                        return ResponseEntity.ok()
                                        .contentType(contentType)
                                        .header(HttpHeaders.CONTENT_DISPOSITION, disposition.toString())
                                        .body(resource);

                } catch (IllegalArgumentException e) {
                        return ResponseEntity.notFound().build();

                } catch (Exception e) {
                        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
                }
        }

        private boolean verifySha256(Path filePath, String expectedHash) throws Exception {

                // Support files uploaded before SHA-256 was implemented
                if (expectedHash == null || expectedHash.isBlank()) {
                        return true;
                }

                MessageDigest digest = MessageDigest.getInstance("SHA-256");

                try (InputStream inputStream = Files.newInputStream(filePath)) {

                        byte[] buffer = new byte[8192];
                        int bytesRead;

                        while ((bytesRead = inputStream.read(buffer)) != -1) {
                                digest.update(buffer, 0, bytesRead);
                        }
                }

                String actualHash = HexFormat.of().formatHex(digest.digest());

                return MessageDigest.isEqual(
                                expectedHash.getBytes(StandardCharsets.US_ASCII),
                                actualHash.getBytes(StandardCharsets.US_ASCII));
        }
}
