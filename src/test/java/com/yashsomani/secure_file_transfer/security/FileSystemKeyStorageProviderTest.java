
package com.yashsomani.secure_file_transfer.security;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Files;
import java.nio.file.Path;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class FileSystemKeyStorageProviderTest {

    @TempDir
    Path tempDirectory;

    private SecretKey generateKey() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        return generator.generateKey();
    }

    @Test
    void shouldStoreAndLoadKey() throws Exception {

        FileSystemKeyStorageProvider provider = new FileSystemKeyStorageProvider(tempDirectory);

        SecretKey originalKey = generateKey();

        provider.storeKey("v2", originalKey);

        SecretKey loadedKey = provider.loadKey("v2");

        assertArrayEquals(
                originalKey.getEncoded(),
                loadedKey.getEncoded());
    }

    @Test
    void shouldRegisterNewKeyVersion() throws Exception {

        FileSystemKeyStorageProvider provider = new FileSystemKeyStorageProvider(tempDirectory);

        provider.storeKey("v2", generateKey());

        Path registry = tempDirectory.resolve("key-registry.txt");

        assertTrue(Files.exists(registry));
        assertTrue(Files.readAllLines(registry).contains("v2"));
    }

    @Test
    void shouldRejectMissingRegisteredKey() throws Exception {

        FileSystemKeyStorageProvider provider = new FileSystemKeyStorageProvider(tempDirectory);

        provider.storeKey("v2", generateKey());

        Files.delete(tempDirectory.resolve("aes-256-v2.key"));

        assertThrows(
                IllegalStateException.class,
                () -> provider.loadKey("v2"));
    }

    @Test
    void shouldNotOverwriteExistingKey() throws Exception {

        FileSystemKeyStorageProvider provider = new FileSystemKeyStorageProvider(tempDirectory);

        SecretKey originalKey = generateKey();

        provider.storeKey("v2", originalKey);

        assertThrows(
                IllegalStateException.class,
                () -> provider.storeKey("v2", generateKey()));

        SecretKey loadedKey = provider.loadKey("v2");

        assertArrayEquals(
                originalKey.getEncoded(),
                loadedKey.getEncoded());
    }

    @Test
    void shouldRejectKeyCreationForPreviouslyRegisteredVersion()
            throws Exception {

        FileSystemKeyStorageProvider provider = new FileSystemKeyStorageProvider(tempDirectory);

        // Simulate a crash after registration but before key creation.
        Files.writeString(
                tempDirectory.resolve("key-registry.txt"),
                "v2" + System.lineSeparator());

        assertThrows(
                IllegalStateException.class,
                () -> provider.storeKey("v2", generateKey()));

        assertFalse(
                Files.exists(tempDirectory.resolve("aes-256-v2.key")));
    }
}
