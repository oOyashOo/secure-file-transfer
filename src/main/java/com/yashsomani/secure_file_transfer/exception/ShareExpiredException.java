package com.yashsomani.secure_file_transfer.exception;

/**
 * Thrown when a share reference is accessed but is no longer valid
 * because it has expired, been revoked, or never existed.
 */
public class ShareExpiredException extends RuntimeException {

    public ShareExpiredException(String message) {
        super(message);
    }
}