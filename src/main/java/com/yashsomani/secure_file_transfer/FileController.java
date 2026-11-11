package com.yashsomani.secure_file_transfer;

import com.yashsomani.secure_file_transfer.service.FileService;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/files")
public class FileController {

    private final FileService fileService;

    public FileController(FileService fileService) {
        this.fileService = fileService;
    }

    @GetMapping("/my-files")
    public ResponseEntity<?> getMyFiles(Authentication authentication) {

        List<FileMetadata> files =
                fileService.getMyFiles(authentication.getName());

        List<Map<String, Object>> response = files.stream()
                .map(file -> {
                    Map<String, Object> data = new LinkedHashMap<>();

                    data.put("id", file.getId());
                    data.put("originalFilename", file.getOriginalFilename());
                    data.put("contentType", file.getContentType());
                    data.put("fileSize", file.getFileSize());
                    data.put("uploadedAt", file.getUploadedAt());

                    return data;
                })
                .toList();

        return ResponseEntity.ok(response);
    }
}