package com.yashsomani.secure_file_transfer.repository;

import com.yashsomani.secure_file_transfer.FileMetadata;
import com.yashsomani.secure_file_transfer.User;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface FileRepository
        extends JpaRepository<FileMetadata, Long> {

    List<FileMetadata> findByOwnerOrderByUploadedAtDesc(User owner);

    Optional<FileMetadata> findByIdAndOwner(Long id, User owner);

    Optional<FileMetadata> findByEncryptedFilename(String encryptedFilename);

    void deleteByIdAndOwner(Long id, User owner);
}