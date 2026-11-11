package com.yashsomani.secure_file_transfer;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.security.MessageDigest;
import java.util.HexFormat;
import com.yashsomani.secure_file_transfer.security.KeyStorageProvider;

@Service
public class FileEncryptionService {

    private static final int KEY_SIZE = 256;
    private static final int NONCE_SIZE = 12;
    private static final int TAG_SIZE = 128;
    private static final String CURRENT_KEY_VERSION = "v2";

    private final KeyStorageProvider keyStorageProvider;

    public FileEncryptionService(KeyStorageProvider keyStorageProvider) {
        this.keyStorageProvider = keyStorageProvider;
    }

    private final Path encryptedDirectory = Paths.get("encrypted-uploads").toAbsolutePath().normalize();

    private final Path decryptedDirectory = Paths.get("decrypted-uploads").toAbsolutePath().normalize();

    public EncryptionResult encryptFile(MultipartFile file) throws Exception {

        Files.createDirectories(encryptedDirectory);

        SecretKey secretKey = loadOrCreateKey(CURRENT_KEY_VERSION);

        byte[] nonce = new byte[NONCE_SIZE];
        new SecureRandom().nextBytes(nonce);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        cipher.init(
                Cipher.ENCRYPT_MODE,
                secretKey,
                new GCMParameterSpec(TAG_SIZE, nonce));

        String originalName = file.getOriginalFilename();

        if (originalName == null || originalName.isBlank()) {
            originalName = "uploaded-file";
        }

        originalName = Paths.get(originalName)
                .getFileName().toString();

        String encryptedFileName = UUID.randomUUID() + "_" + originalName + ".enc";

        Path destination = encryptedDirectory.resolve(encryptedFileName);

        try (
                InputStream inputStream = file.getInputStream();
                OutputStream outputStream = Files.newOutputStream(
                        destination,
                        StandardOpenOption.CREATE_NEW)) {
            outputStream.write(nonce);

            byte[] buffer = new byte[8192];
            int bytesRead;

            while ((bytesRead = inputStream.read(buffer)) != -1) {
                byte[] encrypted = cipher.update(buffer, 0, bytesRead);

                if (encrypted != null) {
                    outputStream.write(encrypted);
                }
            }

            byte[] finalBytes = cipher.doFinal();
            outputStream.write(finalBytes);
        }

        return new EncryptionResult(
                encryptedFileName,
                CURRENT_KEY_VERSION);
    }

    // Calculate SHA-256 hash of the original file
    public String calculateSha256(MultipartFile file) throws Exception {

        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        try (InputStream inputStream = file.getInputStream()) {

            byte[] buffer = new byte[8192];
            int bytesRead;

            while ((bytesRead = inputStream.read(buffer)) != -1) {
                digest.update(buffer, 0, bytesRead);
            }
        }

        return HexFormat.of().formatHex(digest.digest());
    }

    public String decryptFile(String encryptedFileName, String keyVersion)
            throws Exception {

        Files.createDirectories(decryptedDirectory);

        encryptedFileName = Paths.get(encryptedFileName)
                .getFileName().toString();

        Path encryptedPath = encryptedDirectory.resolve(encryptedFileName).normalize();

        if (!encryptedPath.startsWith(encryptedDirectory)
                || !Files.isRegularFile(encryptedPath)) {
            throw new IOException("Encrypted file not found!");
        }

        if (!encryptedFileName.endsWith(".enc")) {
            throw new IOException("Invalid encrypted file!");
        }

        String storedName = encryptedFileName.substring(
                0, encryptedFileName.length() - 4);

        int separator = storedName.indexOf('_');

        if (separator == -1 || separator == storedName.length() - 1) {
            throw new IOException("Invalid encrypted file name!");
        }
        String fileId = storedName.substring(0, separator);

        String originalName = storedName.substring(separator + 1);

        String decryptedFileName = fileId + "_" + originalName;

        Path destination = decryptedDirectory.resolve(decryptedFileName);

        SecretKey secretKey = loadExistingKey(keyVersion);

        Path temporaryFile = Files.createTempFile(
                decryptedDirectory, "decrypt-", ".tmp");

        boolean successful = false;

        try (
                InputStream inputStream = Files.newInputStream(encryptedPath);
                OutputStream outputStream = Files.newOutputStream(temporaryFile)) {
            byte[] nonce = inputStream.readNBytes(NONCE_SIZE);

            if (nonce.length != NONCE_SIZE) {
                throw new IOException("Invalid encrypted file!");
            }

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

            cipher.init(
                    Cipher.DECRYPT_MODE,
                    secretKey,
                    new GCMParameterSpec(TAG_SIZE, nonce));

            byte[] buffer = new byte[8192];
            int bytesRead;

            while ((bytesRead = inputStream.read(buffer)) != -1) {

                byte[] decrypted = cipher.update(buffer, 0, bytesRead);

                if (decrypted != null) {
                    outputStream.write(decrypted);
                }
            }

            // Verifies the GCM authentication tag
            byte[] finalBytes = cipher.doFinal();
            outputStream.write(finalBytes);

        } catch (Exception e) {
            Files.deleteIfExists(temporaryFile);
            throw e;
        }

        try {
            Files.move(
                    temporaryFile,
                    destination,
                    StandardCopyOption.REPLACE_EXISTING);

            successful = true;

        } finally {
            if (!successful) {
                Files.deleteIfExists(temporaryFile);
            }
        }

        return decryptedFileName;
    }

    private SecretKey loadOrCreateKey(String keyVersion) throws Exception {

        if (keyStorageProvider.keyExists(keyVersion)) {
            return keyStorageProvider.loadKey(keyVersion);
        }

        // Never regenerate a missing v1 key if encrypted files exist.
        if ("v1".equals(keyVersion) && Files.exists(encryptedDirectory)) {

            try (var files = Files.list(encryptedDirectory)) {

                boolean encryptedFilesExist = files
                        .anyMatch(path -> path.getFileName()
                                .toString().endsWith(".enc"));

                if (encryptedFilesExist) {
                    throw new IllegalStateException(
                            "Original v1 AES key is missing. "
                                    + "Refusing to generate a replacement.");
                }
            }
        }

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(KEY_SIZE);

        SecretKey secretKey = keyGenerator.generateKey();

        try {
            keyStorageProvider.storeKey(keyVersion, secretKey);
            return secretKey;

        } catch (java.nio.file.FileAlreadyExistsException e) {
            return keyStorageProvider.loadKey(keyVersion);
        }
    }

    private SecretKey loadExistingKey(String keyVersion) throws Exception {
        return keyStorageProvider.loadKey(keyVersion);
    }

    public void deleteStoredFiles(String encryptedFileName) throws IOException {

        // Sanitize encrypted filename
        String safeName = Paths.get(encryptedFileName)
                .getFileName()
                .toString();

        if (!safeName.endsWith(".enc")) {
            throw new IOException("Invalid encrypted filename!");
        }

        // Extract UUID
        String storedName = safeName.substring(0, safeName.length() - 4);

        int separator = storedName.indexOf('_');

        if (separator == -1) {
            throw new IOException("Invalid encrypted filename!");
        }

        String fileId = storedName.substring(0, separator);

        // Validate encrypted file path
        Path encryptedPath = encryptedDirectory.resolve(safeName).normalize();

        if (!encryptedPath.startsWith(encryptedDirectory)) {
            throw new IOException("Invalid file path!");
        }

        // Delete matching decrypted copies first
        if (Files.exists(decryptedDirectory)) {

            try (var files = Files.list(decryptedDirectory)) {

                var decryptedFiles = files
                        .filter(path -> path.getFileName()
                                .toString()
                                .startsWith(fileId + "_"))
                        .toList();

                for (Path path : decryptedFiles) {
                    Files.deleteIfExists(path);
                }
            }
        }

        // Delete encrypted file
        Files.deleteIfExists(encryptedPath);
    }
}