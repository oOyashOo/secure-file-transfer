package com.yashsomani.secure_file_transfer.security;

import javax.crypto.SecretKey;

public interface KeyStorageProvider {

    void storeKey(String keyVersion, SecretKey secretKey) throws Exception;

    SecretKey loadKey(String keyVersion) throws Exception;

    boolean keyExists(String keyVersion) throws Exception;
}
