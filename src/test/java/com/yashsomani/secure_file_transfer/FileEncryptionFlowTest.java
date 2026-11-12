package com.yashsomani.secure_file_transfer;

import com.yashsomani.secure_file_transfer.security.FileSystemKeyStorageProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.mock.web.MockMultipartFile;

import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifies the full upload encryption flow is preserved for a legitimate
 * upload (Phase 4 requirement: "normal encrypted upload still succeeds").
 *
 * <p>A real PDF is fed through {@link FileEncryptionService#encryptFile},
 * producing a server-generated UUID-based {@code .enc} artifact, then
 * decrypted back and compared byte-for-byte. The AES-256-GCM flow must
 * be unaffected by upload validation.</p>
 */
class FileEncryptionFlowTest {

    @TempDir
    Path keyDirectory;

    @Test
    void normalEncryptedUploadSucceedsAndRoundTrips() throws Exception {
        // A minimal but valid PDF document (%PDF-1.4 header + EOF marker).
        byte[] pdfContent = (
                "%PDF-1.4\n" +
                "1 0 obj\n<< /Type /Catalog >>\nendobj\n" +
                "trailer\n<< /Root 1 0 R >>\n" +
                "%%EOF\n"
        ).getBytes(java.nio.charset.StandardCharsets.US_ASCII);

        MockMultipartFile pdf = new MockMultipartFile(
                "file", "report.pdf", "application/pdf", pdfContent);

        FileEncryptionService encryptionService =
                new FileEncryptionService(new FileSystemKeyStorageProvider(keyDirectory));

        // 1. Encrypt — the storage name must be server-generated (UUID-based),
        //    not client-controlled.
        EncryptionResult result = encryptionService.encryptFile(pdf);

        assertNotNull(result.encryptedFilename());
        assertTrue(result.encryptedFilename().endsWith(".enc"),
                "Encrypted artifact must end in .enc");
        assertTrue(result.encryptedFilename().matches("[0-9a-fA-F-]{36}_.*\\.enc"),
                "Storage filename must be prefixed with a UUID, was: "
                        + result.encryptedFilename());
        assertNotNull(result.keyVersion());

        // The encrypted artifact must exist on disk.
        Path encryptedPath = Paths.get("encrypted-uploads")
                .toAbsolutePath()
                .normalize()
                .resolve(result.encryptedFilename());
        assertTrue(Files.isRegularFile(encryptedPath),
                "Encrypted file should exist at " + encryptedPath);

        try {
            // 2. Decrypt back to a stream (Phase 3 streaming path) and compare.
            ByteArrayOutputStream plaintext = new ByteArrayOutputStream();
            encryptionService.decryptFileToStream(
                    result.encryptedFilename(),
                    result.keyVersion(),
                    plaintext);

            assertArrayEquals(pdfContent, plaintext.toByteArray(),
                    "Decrypted plaintext must match the original file exactly");
        } finally {
            // Clean up the transient encrypted artifact (gitignored dir).
            Files.deleteIfExists(encryptedPath);
        }
    }
}
