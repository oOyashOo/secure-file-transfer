package com.yashsomani.secure_file_transfer;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Entry point for the Secure File Transfer System.
 *
 * <p>Method-level security is enabled in {@link SecurityConfig} so that
 * authorization can be enforced declaratively in later phases.</p>
 */
@SpringBootApplication
public class SecureFileTransferApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecureFileTransferApplication.class, args);
	}

}
