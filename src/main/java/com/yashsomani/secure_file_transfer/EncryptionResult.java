package com.yashsomani.secure_file_transfer;

public record EncryptionResult(
        String encryptedFilename,
        String keyVersion
) {
}
