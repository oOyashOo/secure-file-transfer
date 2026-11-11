
package com.yashsomani.secure_file_transfer.dto;

import java.time.LocalDateTime;

public class FileShareResponse {

    private Long shareId;
    private Long fileId;
    private String fileName;
    private String contentType;
    private Long fileSize;
    private String senderUsername;
    private String recipientUsername;
    private LocalDateTime sharedAt;

    public FileShareResponse(
            Long shareId,
            Long fileId,
            String fileName,
            String contentType,
            Long fileSize,
            String senderUsername,
            String recipientUsername,
            LocalDateTime sharedAt) {

        this.shareId = shareId;
        this.fileId = fileId;
        this.fileName = fileName;
        this.contentType = contentType;
        this.fileSize = fileSize;
        this.senderUsername = senderUsername;
        this.recipientUsername = recipientUsername;
        this.sharedAt = sharedAt;
    }

    public Long getShareId() {
        return shareId;
    }

    public Long getFileId() {
        return fileId;
    }

    public String getFileName() {
        return fileName;
    }

    public String getContentType() {
        return contentType;
    }

    public Long getFileSize() {
        return fileSize;
    }

    public String getSenderUsername() {
        return senderUsername;
    }

    public String getRecipientUsername() {
        return recipientUsername;
    }

    public LocalDateTime getSharedAt() {
        return sharedAt;
    }
}

