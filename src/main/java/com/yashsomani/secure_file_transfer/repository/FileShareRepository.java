
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

    /**
     * Fetches a share together with its file in a single query so the file
     * association is initialized before the transaction closes. This keeps
     * {@code spring.jpa.open-in-view=false} safe for the shared-download path.
     */
    @org.springframework.data.jpa.repository.Query(
            "SELECT fs FROM FileShare fs "
                    + "JOIN FETCH fs.file f "
                    + "WHERE fs.id = :id "
                    + "AND fs.recipient = :recipient "
                    + "AND fs.revoked = false"
    )
    Optional<FileShare> findWithFileByIdAndRecipientAndRevokedFalse(
            Long id, User recipient
    );

    boolean existsByFileAndRecipientAndRevokedFalse(
            FileMetadata file, User recipient
    );

    void deleteByFile(FileMetadata file);
}
