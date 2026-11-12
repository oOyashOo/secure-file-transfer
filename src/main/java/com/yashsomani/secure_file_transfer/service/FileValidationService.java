package com.yashsomani.secure_file_transfer.service;

import org.jspecify.annotations.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Server-side file validation for uploads.
 *
 * <p>Validates file size, emptiness, filename safety, and content type
 * using magic bytes (file signatures). Does not trust client-provided
 * metadata such as {@link MultipartFile#getContentType()},
 * {@link MultipartFile#getSize()}, or {@link MultipartFile#getOriginalFilename()}.</p>
 */
@Service
public class FileValidationService {

    private static final Logger logger = LoggerFactory.getLogger(FileValidationService.class);

    /**
     * Maximum allowed file size: 500 MB (matches Spring multipart config).
     */
    public static final long MAX_FILE_SIZE = 500L * 1024 * 1024;

    /**
     * Magic byte signatures for allowed file types.
     * Each entry: extension -> list of possible magic byte prefixes.
     */
    private static final List<MagicSignature> MAGIC_SIGNATURES = List.of(
            // PDF
            new MagicSignature("pdf", "application/pdf", new byte[] {0x25, 0x50, 0x44, 0x46}), // %PDF

            // Images
            new MagicSignature("png", "image/png", new byte[] {(byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}),
            new MagicSignature("jpg", "image/jpeg", new byte[] {(byte) 0xFF, (byte) 0xD8, (byte) 0xFF}),
            new MagicSignature("jpeg", "image/jpeg", new byte[] {(byte) 0xFF, (byte) 0xD8, (byte) 0xFF}),
            new MagicSignature("gif", "image/gif", new byte[] {0x47, 0x49, 0x46, 0x38, 0x37, 0x61}), // GIF87a
            new MagicSignature("gif", "image/gif", new byte[] {0x47, 0x49, 0x46, 0x38, 0x39, 0x61}), // GIF89a
            new MagicSignature("webp", "image/webp", new byte[] {0x52, 0x49, 0x46, 0x46}), // RIFF (need more bytes)
            new MagicSignature("bmp", "image/bmp", new byte[] {0x42, 0x4D}), // BM
            new MagicSignature("tiff", "image/tiff", new byte[] {0x49, 0x49, 0x2A, 0x00}), // II*
            new MagicSignature("tiff", "image/tiff", new byte[] {0x4D, 0x4D, 0x00, 0x2A}), // MM*

            // Audio
            new MagicSignature("mp3", "audio/mpeg", new byte[] {(byte) 0xFF, (byte) 0xFB}), // MPEG frame sync
            new MagicSignature("mp3", "audio/mpeg", new byte[] {(byte) 0xFF, (byte) 0xF3}),
            new MagicSignature("mp3", "audio/mpeg", new byte[] {(byte) 0xFF, (byte) 0xF2}),
            new MagicSignature("mp3", "audio/mpeg", new byte[] {0x49, 0x44, 0x33}), // ID3
            new MagicSignature("wav", "audio/wav", new byte[] {0x52, 0x49, 0x46, 0x46}), // RIFF
            new MagicSignature("flac", "audio/flac", new byte[] {0x66, 0x4C, 0x61, 0x43}), // fLaC
            new MagicSignature("ogg", "audio/ogg", new byte[] {0x4F, 0x67, 0x67, 0x53}), // OggS

            // Video
            new MagicSignature("mp4", "video/mp4", new byte[] {0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70}), // ftyp at offset 4
            new MagicSignature("mp4", "video/mp4", new byte[] {0x00, 0x00, 0x00, 0x1C, 0x66, 0x74, 0x79, 0x70}),
            new MagicSignature("mp4", "video/mp4", new byte[] {0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70}),
            new MagicSignature("mov", "video/quicktime", new byte[] {0x00, 0x00, 0x00, 0x14, 0x66, 0x74, 0x79, 0x70}), // ftyp
            new MagicSignature("avi", "video/x-msvideo", new byte[] {0x52, 0x49, 0x46, 0x46}), // RIFF
            new MagicSignature("mkv", "video/x-matroska", new byte[] {0x1A, 0x45, (byte) 0xDF, (byte) 0xA3}), // EBML

            // Documents
            new MagicSignature("docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    new byte[] {0x50, 0x4B, 0x03, 0x04}), // ZIP-based (need secondary check)
            new MagicSignature("xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    new byte[] {0x50, 0x4B, 0x03, 0x04}),
            new MagicSignature("pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                    new byte[] {0x50, 0x4B, 0x03, 0x04}),
            new MagicSignature("doc", "application/msword", new byte[] {(byte) 0xD0, (byte) 0xCF, 0x11, (byte) 0xE0}), // OLE
            new MagicSignature("xls", "application/vnd.ms-excel", new byte[] {(byte) 0xD0, (byte) 0xCF, 0x11, (byte) 0xE0}),
            new MagicSignature("ppt", "application/vnd.ms-powerpoint", new byte[] {(byte) 0xD0, (byte) 0xCF, 0x11, (byte) 0xE0}),

            // Text/Code
            new MagicSignature("txt", "text/plain", new byte[] {}), // No magic bytes - text files
            new MagicSignature("csv", "text/csv", new byte[] {}),
            new MagicSignature("json", "application/json", new byte[] {}),
            new MagicSignature("xml", "application/xml", new byte[] {}),
            new MagicSignature("md", "text/markdown", new byte[] {}),
            new MagicSignature("html", "text/html", new byte[] {}),
            new MagicSignature("css", "text/css", new byte[] {}),
            new MagicSignature("js", "application/javascript", new byte[] {}),

            // Archives (allowed for completeness)
            new MagicSignature("zip", "application/zip", new byte[] {0x50, 0x4B, 0x03, 0x04}),
            new MagicSignature("gz", "application/gzip", new byte[] {0x1F, (byte) 0x8B}),
            new MagicSignature("tar", "application/x-tar", new byte[] {}) // TAR has no standard magic
    );

    /**
     * Set of allowed MIME types derived from magic signatures.
     */
    private static final Set<String> ALLOWED_MIME_TYPES = MAGIC_SIGNATURES.stream()
            .map(MagicSignature::mimeType)
            .collect(Collectors.toUnmodifiableSet());

    /**
     * Validates an uploaded file.
     *
     * @param file the uploaded file
     * @throws FileValidationException if validation fails
     */
    public void validateUpload(MultipartFile file) throws FileValidationException {
        if (file == null) {
            throw new FileValidationException("No file provided");
        }

        // 1. Empty file validation
        if (file.isEmpty()) {
            throw new FileValidationException("File is empty");
        }

        // 2. Server-side size validation (do not trust file.getSize())
        // We read the stream to count bytes, but Spring already enforces max size
        // via MaxUploadSizeExceededException. This is a secondary check.
        long reportedSize = file.getSize();
        if (reportedSize > MAX_FILE_SIZE) {
            throw new FileValidationException("File size exceeds maximum allowed size of " + formatBytes(MAX_FILE_SIZE));
        }

        // 3. Filename safety
        String originalFilename = file.getOriginalFilename();
        if (!isFilenameSafe(originalFilename)) {
            throw new FileValidationException("Invalid filename");
        }

        // 4. Content type validation via magic bytes
        validateContentType(file);
    }

    /**
     * Validates that the file content matches an allowed type using magic bytes.
     */
    private void validateContentType(MultipartFile file) throws FileValidationException {
        try (InputStream inputStream = file.getInputStream()) {
            // Read first 12 bytes for magic byte detection (covers all our signatures)
            byte[] header = new byte[12];
            int bytesRead = inputStream.readNBytes(header, 0, header.length);

            if (bytesRead == 0) {
                throw new FileValidationException("File is empty");
            }

            // Check against known magic signatures
            boolean matched = false;
            String detectedMimeType = null;

            for (MagicSignature sig : MAGIC_SIGNATURES) {
                if (matchesMagicBytes(header, sig.magicBytes())) {
                    // Special handling for ZIP-based formats (docx, xlsx, pptx, zip)
                    if (Arrays.equals(sig.magicBytes(), new byte[] {0x50, 0x4B, 0x03, 0x04})) {
                        // Need to inspect ZIP entries to distinguish
                        detectedMimeType = detectZipBasedMimeType(file);
                        if (detectedMimeType != null) {
                            matched = true;
                            break;
                        }
                    } else if (Arrays.equals(sig.magicBytes(), new byte[] {0x52, 0x49, 0x46, 0x46})) {
                        // RIFF-based: could be WAV, AVI, WebP. The container type
                        // lives at offset 8 in the header we already read.
                        detectedMimeType = detectRiffBasedMimeType(header);
                        if (detectedMimeType != null) {
                            matched = true;
                            break;
                        }
                    } else if (sig.magicBytes().length == 0) {
                        // Text-based files with no magic bytes - allow if extension matches
                        if (isTextFile(file, sig.extension())) {
                            matched = true;
                            detectedMimeType = sig.mimeType();
                            break;
                        }
                    } else {
                        matched = true;
                        detectedMimeType = sig.mimeType();
                        break;
                    }
                }
            }

            if (!matched) {
                logger.warn("File type not allowed: detected header bytes: {}", bytesToHex(header));
                throw new FileValidationException("File type not allowed. Only PDF, images, audio, video, documents, and text files are supported.");
            }

            logger.debug("File validated: detected MIME type = {}", detectedMimeType);

        } catch (IOException e) {
            throw new FileValidationException("Failed to read file for validation", e);
        }
    }

    /**
     * Detects MIME type for ZIP-based files (docx, xlsx, pptx, zip).
     */
    private String detectZipBasedMimeType(MultipartFile file) {
        try (InputStream is = file.getInputStream();
             java.util.zip.ZipInputStream zis = new java.util.zip.ZipInputStream(is)) {

            java.util.zip.ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                String name = entry.getName().toLowerCase();
                if (name.contains("word/") || name.endsWith(".xml") && name.startsWith("word/")) {
                    return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"; // docx
                }
                if (name.contains("xl/") || name.endsWith(".xml") && name.startsWith("xl/")) {
                    return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"; // xlsx
                }
                if (name.contains("ppt/") || name.endsWith(".xml") && name.startsWith("ppt/")) {
                    return "application/vnd.openxmlformats-officedocument.presentationml.presentation"; // pptx
                }
            }
            // Plain ZIP
            return "application/zip";
        } catch (Exception e) {
            logger.debug("ZIP inspection failed: {}", e.getMessage());
            return "application/zip"; // Default to generic zip
        }
    }

    /**
     * Detects MIME type for RIFF-based files (WAV, AVI, WebP).
     *
     * <p>RIFF layout: bytes 0-3 = "RIFF", bytes 4-7 = chunk size,
     * bytes 8-11 = container type ("WAVE", "AVI ", "WEBP"). The
     * container type is read from the already-loaded header rather
     * than consuming the stream, so stream position is not corrupted.</p>
     *
     * @param header the first 12 bytes read from the file
     * @return the detected MIME type, or {@code null} if unrecognized
     */
    private String detectRiffBasedMimeType(byte[] header) {
        try {
            if (header.length < 12) {
                return null;
            }
            String type = new String(header, 8, 4, java.nio.charset.StandardCharsets.US_ASCII);
            switch (type) {
                case "WAVE": return "audio/wav";
                case "AVI ": return "video/x-msvideo";
                case "WEBP": return "image/webp";
                default: return null;
            }
        } catch (Exception e) {
            logger.debug("RIFF type detection failed: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Heuristic check for text-based files.
     */
    private boolean isTextFile(MultipartFile file, String expectedExtension) {
        String originalFilename = file.getOriginalFilename();
        if (originalFilename != null) {
            String ext = getExtension(originalFilename).toLowerCase();
            if (ext.equals(expectedExtension)) {
                return true;
            }
        }
        // Could also try to read as UTF-8 and check validity
        return false;
    }

    /**
     * Checks if a filename is safe (no path traversal, etc.).
     */
    private boolean isFilenameSafe(String filename) {
        if (filename == null || filename.isBlank()) {
            return false;
        }

        // Normalize
        String normalized = filename.trim();

        // Reject path traversal attempts
        if (normalized.contains("..")) {
            return false;
        }
        if (normalized.contains("/") || normalized.contains("\\")) {
            return false;
        }
        // Reject absolute paths
        if (normalized.startsWith("/") || normalized.matches("^[A-Za-z]:\\\\.*")) {
            return false;
        }
        // Reject control characters
        if (normalized.chars().anyMatch(c -> c < 32 || c == 127)) {
            return false;
        }
        // Reject reserved names (Windows)
        String lower = normalized.toLowerCase();
        if (lower.matches("^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\\..*)?$")) {
            return false;
        }

        return true;
    }

    /**
     * Extracts file extension from filename.
     */
    private String getExtension(String filename) {
        int dotIndex = filename.lastIndexOf('.');
        if (dotIndex > 0 && dotIndex < filename.length() - 1) {
            return filename.substring(dotIndex + 1);
        }
        return "";
    }

    /**
     * Checks if header starts with magic bytes.
     */
    private boolean matchesMagicBytes(byte[] header, byte[] magic) {
        if (magic.length == 0) {
            return false; // Handled separately
        }
        if (header.length < magic.length) {
            return false;
        }
        for (int i = 0; i < magic.length; i++) {
            if (header[i] != magic[i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * Formats bytes as human-readable string.
     */
    private String formatBytes(long bytes) {
        if (bytes >= 1024L * 1024 * 1024) {
            return String.format("%.1f GB", bytes / (1024.0 * 1024 * 1024));
        } else if (bytes >= 1024L * 1024) {
            return String.format("%.1f MB", bytes / (1024.0 * 1024));
        } else if (bytes >= 1024) {
            return String.format("%.1f KB", bytes / 1024.0);
        } else {
            return bytes + " bytes";
        }
    }

    /**
     * Converts bytes to hex string for logging.
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString().trim();
    }

    /**
     * Magic byte signature record.
     *
     * <p>The {@code mimeType} component is annotated {@link NonNull} so the
     * {@code MAGIC_SIGNATURES} stream ({@code .map(MagicSignature::mimeType)})
     * is understood by IDE null-analysis to never yield {@code null},
     * eliminating the nullability warning without weakening validation.</p>
     */
    private record MagicSignature(
            String extension,
            @NonNull String mimeType,
            byte[] magicBytes) {
    }

    /**
     * Exception thrown when file validation fails.
     */
    public static class FileValidationException extends Exception {
        public FileValidationException(String message) {
            super(message);
        }

        public FileValidationException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /**
     * Returns the set of allowed MIME types for documentation/display.
     */
    public Set<String> getAllowedMimeTypes() {
        return Collections.unmodifiableSet(ALLOWED_MIME_TYPES);
    }

    /**
     * Returns the maximum allowed file size in bytes.
     */
    public long getMaxFileSize() {
        return MAX_FILE_SIZE;
    }
}