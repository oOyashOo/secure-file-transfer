
package com.yashsomani.secure_file_transfer.service;

import com.yashsomani.secure_file_transfer.User;
import com.yashsomani.secure_file_transfer.FileMetadata;
import com.yashsomani.secure_file_transfer.dto.FileShareResponse;
import com.yashsomani.secure_file_transfer.entity.FileShare;
import com.yashsomani.secure_file_transfer.repository.UserRepository;
import com.yashsomani.secure_file_transfer.repository.FileRepository;
import com.yashsomani.secure_file_transfer.repository.FileShareRepository;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class FileShareService {

    private final FileShareRepository fileShareRepository;
    private final FileRepository fileRepository;
    private final UserRepository userRepository;

    public FileShareService(
            FileShareRepository fileShareRepository,
            FileRepository fileRepository,
            UserRepository userRepository) {

        this.fileShareRepository = fileShareRepository;
        this.fileRepository = fileRepository;
        this.userRepository = userRepository;
    }

    // Convert FileShare entity into DTO
    private FileShareResponse convertToResponse(FileShare share) {

        FileMetadata file = share.getFile();

        return new FileShareResponse(
                share.getId(),
                file.getId(),
                file.getOriginalFilename(),
                file.getContentType(),
                file.getFileSize(),
                share.getSender().getUsername(),
                share.getRecipient().getUsername(),
                share.getSharedAt());
    }

    // Share a file with another user
    @Transactional
    public FileShareResponse shareFile(
            Long fileId,
            String recipientEmail,
            String senderEmail) {

        User sender = userRepository.findByEmail(senderEmail)
                .orElseThrow(() -> new IllegalArgumentException("Sender not found"));

        User recipient = userRepository.findByEmail(recipientEmail)
                .orElseThrow(() -> new IllegalArgumentException("Recipient not found"));

        if (sender.getId().equals(recipient.getId())) {
            throw new IllegalArgumentException(
                    "You cannot share a file with yourself");
        }

        FileMetadata file = fileRepository
                .findByIdAndOwner(fileId, sender)
                .orElseThrow(() -> new IllegalArgumentException(
                        "File not found or access denied"));

        if (fileShareRepository
                .existsByFileAndRecipientAndRevokedFalse(file, recipient)) {
            throw new IllegalArgumentException(
                    "File is already shared with this user");
        }

        FileShare fileShare = new FileShare();

        fileShare.setFile(file);
        fileShare.setSender(sender);
        fileShare.setRecipient(recipient);

        FileShare savedShare = fileShareRepository.save(fileShare);

        return convertToResponse(savedShare);
    }

    // Get files shared with the logged-in user
    @Transactional(readOnly = true)
    public List<FileShareResponse> getSharedWithMe(String email) {

        User recipient = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        return fileShareRepository
                .findByRecipientAndRevokedFalseOrderBySharedAtDesc(recipient)
                .stream()
                .map(this::convertToResponse)
                .toList();
    }

    // Get files shared by the logged-in user
    @Transactional(readOnly = true)
    public List<FileShareResponse> getSharedByMe(String email) {

        User sender = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        return fileShareRepository
                .findBySenderAndRevokedFalseOrderBySharedAtDesc(sender)
                .stream()
                .map(this::convertToResponse)
                .toList();
    }

    // Get a file shared with the logged-in recipient
    @Transactional(readOnly = true)
    public FileMetadata getSharedFile(Long shareId, String recipientEmail) {

        User recipient = userRepository.findByEmail(recipientEmail)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        FileShare share = fileShareRepository
                .findByIdAndRecipientAndRevokedFalse(shareId, recipient)
                .orElseThrow(() -> new IllegalArgumentException(
                        "Shared file not found or access denied"));

        return share.getFile();
    }

    // Revoke sharing access
    @Transactional
    public void revokeShare(Long shareId, String senderEmail) {

        User sender = userRepository.findByEmail(senderEmail)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        FileShare share = fileShareRepository.findById(shareId)
                .orElseThrow(() -> new IllegalArgumentException("Share not found"));

        if (!share.getSender().getId().equals(sender.getId())) {
            throw new IllegalArgumentException(
                    "You are not authorized to revoke this share");
        }

        if (share.isRevoked()) {
            throw new IllegalArgumentException(
                    "Sharing access is already revoked");
        }

        share.setRevoked(true);
        fileShareRepository.save(share);
    }
}
