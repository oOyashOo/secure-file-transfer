
package com.yashsomani.secure_file_transfer.repository;

import com.yashsomani.secure_file_transfer.User;
import com.yashsomani.secure_file_transfer.FileMetadata;
import com.yashsomani.secure_file_transfer.entity.FileShare;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface FileShareRepository extends JpaRepository<FileShare, Long> {

    List<FileShare> findByRecipientAndRevokedFalseOrderBySharedAtDesc(User recipient);

    List<FileShare> findBySenderAndRevokedFalseOrderBySharedAtDesc(User sender);

    Optional<FileShare> findByIdAndRecipientAndRevokedFalse(
            Long id, User recipient
    );

    boolean existsByFileAndRecipientAndRevokedFalse(
            FileMetadata file, User recipient
    );

    void deleteByFile(FileMetadata file);
}
