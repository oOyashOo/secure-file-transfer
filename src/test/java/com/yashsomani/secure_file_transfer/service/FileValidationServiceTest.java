package com.yashsomani.secure_file_transfer.service;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.web.multipart.MultipartFile;

import static org.junit.jupiter.api.Assertions.*;

class FileValidationServiceTest {

    private final FileValidationService validationService = new FileValidationService();

    @Test
    void testValidPdfUpload() throws Exception {
        byte[] content = new byte[] {0x25, 0x50, 0x44, 0x46, 0x00, 0x00}; // PDF header
        MockMultipartFile file = new MockMultipartFile("file", "test.pdf", "application/pdf", content);
        assertDoesNotThrow(() -> validationService.validateUpload(file));
    }

    @Test
    void testValidImageUpload() throws Exception {
        byte[] content = new byte[] {(byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}; // PNG header
        MockMultipartFile file = new MockMultipartFile("file", "test.png", "image/png", content);
        assertDoesNotThrow(() -> validationService.validateUpload(file));
    }

    @Test
    void testEmptyFileRejection() {
        MockMultipartFile file = new MockMultipartFile("file", "empty.txt", "text/plain", new byte[0]);
        assertThrows(FileValidationService.FileValidationException.class, () -> validationService.validateUpload(file));
    }

    @Test
    void testUnsupportedFileTypeRejection() {
        byte[] content = new byte[] {0x00, 0x00, 0x00, 0x00}; // Unknown header
        MockMultipartFile file = new MockMultipartFile("file", "test.exe", "application/x-msdownload", content);
        assertThrows(FileValidationService.FileValidationException.class, () -> validationService.validateUpload(file));
    }

    @Test
    void testValidAudioWavUpload() throws Exception {
        // RIFF header: "RIFF" + size + "WAVE"
        byte[] content = new byte[] {
                0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00,
                0x57, 0x41, 0x56, 0x45 // WAVE
        };
        MockMultipartFile file = new MockMultipartFile("file", "clip.wav", "audio/wav", content);
        assertDoesNotThrow(() -> validationService.validateUpload(file));
    }

    @Test
    void testValidVideoAviUpload() throws Exception {
        // RIFF header: "RIFF" + size + "AVI "
        byte[] content = new byte[] {
                0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00,
                0x41, 0x56, 0x49, 0x20 // AVI<space>
        };
        MockMultipartFile file = new MockMultipartFile("file", "movie.avi", "video/x-msvideo", content);
        assertDoesNotThrow(() -> validationService.validateUpload(file));
    }

    @Test
    void testValidImageWebpUpload() throws Exception {
        // RIFF header: "RIFF" + size + "WEBP"
        byte[] content = new byte[] {
                0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00,
                0x57, 0x45, 0x42, 0x50 // WEBP
        };
        MockMultipartFile file = new MockMultipartFile("file", "photo.webp", "image/webp", content);
        assertDoesNotThrow(() -> validationService.validateUpload(file));
    }

    @Test
    void testSpoofedMimeTypeRejection() {
        // Content is an executable (MZ header), but client claims it's a PNG image
        byte[] exeContent = new byte[] {0x4D, 0x5A, (byte) 0x90, 0x00}; // 'M' 'Z' ...
        MockMultipartFile file = new MockMultipartFile("file", "fake_image.png", "image/png", exeContent);
        assertThrows(FileValidationService.FileValidationException.class, () -> validationService.validateUpload(file));
    }

    @Test
    void testOversizedUploadRejection() {
        // Mock a file whose reported size exceeds the 500MB limit without
        // allocating the full array. MultipartFile.getSize() is what the
        // service uses as its secondary size check.
        MultipartFile file = new MockMultipartFile("file", "large.dat", "application/octet-stream", new byte[1024]) {
            @Override
            public long getSize() {
                return FileValidationService.MAX_FILE_SIZE + 1;
            }
        };

        assertThrows(FileValidationService.FileValidationException.class, () -> validationService.validateUpload(file));
    }

    @Test
    void testMaliciousFilenameRejection() {
        // Path traversal attempts
        MockMultipartFile file1 = new MockMultipartFile("file", "../../etc/passwd", "text/plain", "content".getBytes());
        assertThrows(FileValidationService.FileValidationException.class, () -> validationService.validateUpload(file1));

        MockMultipartFile file2 = new MockMultipartFile("file", "..\\..\\windows\\system32\\cmd.exe", "text/plain", "content".getBytes());
        assertThrows(FileValidationService.FileValidationException.class, () -> validationService.validateUpload(file2));

        MockMultipartFile file3 = new MockMultipartFile("file", "/etc/passwd", "text/plain", "content".getBytes());
        assertThrows(FileValidationService.FileValidationException.class, () -> validationService.validateUpload(file3));

        MockMultipartFile file4 = new MockMultipartFile("file", "C:\\boot.ini", "text/plain", "content".getBytes());
        assertThrows(FileValidationService.FileValidationException.class, () -> validationService.validateUpload(file4));

        MockMultipartFile file5 = new MockMultipartFile("file", "null\0byte.txt", "text/plain", "content".getBytes());
        assertThrows(FileValidationService.FileValidationException.class, () -> validationService.validateUpload(file5));

        MockMultipartFile file6 = new MockMultipartFile("file", "sub/dir/escaped.pdf", "application/pdf",
                new byte[] {0x25, 0x50, 0x44, 0x46, 0x00});
        assertThrows(FileValidationService.FileValidationException.class, () -> validationService.validateUpload(file6));

        MockMultipartFile file7 = new MockMultipartFile("file", "CON.txt", "text/plain", "content".getBytes());
        assertThrows(FileValidationService.FileValidationException.class, () -> validationService.validateUpload(file7));
    }

    @Test
    void testNullFileRejection() {
        assertThrows(FileValidationService.FileValidationException.class,
                () -> validationService.validateUpload(null));
    }

    @Test
    void testNullFilenameRejection() {
        MockMultipartFile file = new MockMultipartFile("file", null, "application/pdf",
                new byte[] {0x25, 0x50, 0x44, 0x46, 0x00});
        assertThrows(FileValidationService.FileValidationException.class, () -> validationService.validateUpload(file));
    }
}
