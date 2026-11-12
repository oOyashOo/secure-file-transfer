package com.yashsomani.secure_file_transfer.service;

import com.yashsomani.secure_file_transfer.FileMetadata;
import com.yashsomani.secure_file_transfer.User;
import com.yashsomani.secure_file_transfer.repository.FileRepository;
import com.yashsomani.secure_file_transfer.repository.UserRepository;
import com.yashsomani.secure_file_transfer.EncryptionResult;
import com.yashsomani.secure_file_transfer.FileEncryptionService;
import com.yashsomani.secure_file_transfer.repository.FileShareRepository;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

/**
 * File management service with method-level authorization.
 *
 * <p>Authorization is enforced at the service layer using {@code @PreAuthorize}
 * to ensure that users can only access their own files.</p>
 */
@Service
public class FileService {

    private final FileRepository fileRepository;
    private final UserRepository userRepository;
    private final FileEncryptionService encryptionService;
    private final FileShareRepository fileShareRepository;

    public FileService(
            FileRepository fileRepository,
            UserRepository userRepository,
            FileEncryptionService encryptionService,
            FileShareRepository fileShareRepository) {

        this.fileRepository = fileRepository;
        this.userRepository = userRepository;
        this.encryptionService = encryptionService;
        this.fileShareRepository = fileShareRepository;
    }

    @PreAuthorize("authentication.name == #ownerEmail")
    public FileMetadata uploadFile(
            MultipartFile file,
            String ownerEmail) throws Exception {

        User owner = userRepository.findByEmail(ownerEmail)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        // Calculate SHA-256 hash of the original file
        String hash = encryptionService.calculateSha256(file);

        // Encrypt the original file
        EncryptionResult encryptionResult = encryptionService.encryptFile(file);

        String encryptedFilename = encryptionResult.encryptedFilename();
        String keyVersion = encryptionResult.keyVersion();

        FileMetadata metadata = new FileMetadata();

        metadata.setOriginalFilename(file.getOriginalFilename());
        metadata.setEncryptedFilename(encryptedFilename);
        metadata.setContentType(
                file.getContentType() != null
                        ? file.getContentType()
                        : "application/octet-stream");
        metadata.setFileSize(file.getSize());
        metadata.setSha256Hash(hash);
        metadata.setKeyVersion(keyVersion);
        metadata.setOwner(owner);

        return fileRepository.save(metadata);
    }

    @PreAuthorize("authentication.name == #ownerEmail")
    public List<FileMetadata> getMyFiles(String ownerEmail) {

        User owner = userRepository.findByEmail(ownerEmail)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        return fileRepository.findByOwnerOrderByUploadedAtDesc(owner);
    }

    @PreAuthorize("authentication.name == #ownerEmail")
    public FileMetadata getOwnedFile(
            Long fileId,
            String ownerEmail) {

        User owner = userRepository.findByEmail(ownerEmail)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        return fileRepository.findByIdAndOwner(fileId, owner)
                .orElseThrow(() -> new IllegalArgumentException(
                        "File not found or access denied"));
    }

    @PreAuthorize("authentication.name == #ownerEmail")
    @Transactional
    public void deleteMyFile(Long fileId, String ownerEmail) throws Exception {

        User owner = userRepository.findByEmail(ownerEmail)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        FileMetadata file = fileRepository
                .findByIdAndOwner(fileId, owner)
                .orElseThrow(() -> new IllegalArgumentException(
                        "File not found or access denied"));

        // Delete all sharing records associated with this file
        fileShareRepository.deleteByFile(file);

        // Delete physical encrypted and decrypted files
        encryptionService.deleteStoredFiles(
                file.getEncryptedFilename());

        // Delete database metadata
        fileRepository.delete(file);
    }
}