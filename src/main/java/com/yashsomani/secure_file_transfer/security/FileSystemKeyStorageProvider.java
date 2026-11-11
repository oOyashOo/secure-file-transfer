package com.yashsomani.secure_file_transfer.security;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Component;

@Component
public class FileSystemKeyStorageProvider implements KeyStorageProvider {

    private final Path keyDirectory;
    private final Path registryFile;

    public FileSystemKeyStorageProvider() {
        this(Paths.get("keys").toAbsolutePath().normalize());
    }

    public FileSystemKeyStorageProvider(Path keyDirectory) {
        this.keyDirectory = keyDirectory;
        this.registryFile = keyDirectory.resolve("key-registry.txt");
    }

    private Path getKeyPath(String keyVersion) {

        return switch (keyVersion) {
            case "v1" -> keyDirectory.resolve("aes-256.key");
            case "v2" -> keyDirectory.resolve("aes-256-v2.key");
            default -> throw new IllegalArgumentException(
                    "Unsupported key version: " + keyVersion);
        };
    }

    private java.util.Set<String> loadRegisteredVersions()
            throws Exception {

        if (!Files.exists(registryFile)) {
            return new java.util.HashSet<>();
        }

        return new java.util.HashSet<>(
                Files.readAllLines(registryFile));
    }

    private void registerKeyVersion(String keyVersion)
            throws Exception {

        java.util.Set<String> versions = loadRegisteredVersions();

        if (!versions.contains(keyVersion)) {
            Files.writeString(
                    registryFile,
                    keyVersion + System.lineSeparator(),
                    StandardOpenOption.CREATE,
                    StandardOpenOption.APPEND);
        }
    }

    @Override
    public synchronized void storeKey(String keyVersion, SecretKey secretKey)
            throws Exception {

        Files.createDirectories(keyDirectory);

        Path keyPath = getKeyPath(keyVersion);

        java.util.Set<String> versions = loadRegisteredVersions();

        if (versions.contains(keyVersion)) {
            throw new IllegalStateException(
                    "Previously registered key is missing: " + keyVersion);
        }

        if (Files.exists(keyPath)) {
            throw new IllegalStateException(
                    "Key file already exists but is not registered: " + keyVersion);
        }

        // Register the version before creating the key.
        registerKeyVersion(keyVersion);

        Files.write(
                keyPath,
                secretKey.getEncoded(),
                StandardOpenOption.CREATE_NEW);
    }

    @Override
    public SecretKey loadKey(String keyVersion) throws Exception {

        java.util.Set<String> versions = loadRegisteredVersions();

        Path keyPath = getKeyPath(keyVersion);

        if (versions.contains(keyVersion) && !Files.isRegularFile(keyPath)) {
            throw new IllegalStateException(
                    "Registered AES key is missing: " + keyVersion);
        }

        if (!Files.isRegularFile(keyPath)) {
            throw new IllegalStateException(
                    "Key not found: " + keyVersion);
        }

        byte[] keyBytes = Files.readAllBytes(keyPath);

        if (keyBytes.length != 32) {
            throw new IllegalStateException(
                    "Invalid AES-256 key: " + keyVersion);
        }

        registerKeyVersion(keyVersion);

        return new SecretKeySpec(keyBytes, "AES");
    }

    @Override
    public boolean keyExists(String keyVersion) throws Exception {

        return Files.isRegularFile(getKeyPath(keyVersion));
    }
}
