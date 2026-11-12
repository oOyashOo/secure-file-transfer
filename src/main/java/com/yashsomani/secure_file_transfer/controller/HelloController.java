package com.yashsomani.secure_file_transfer.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @GetMapping("/api/hello")
    public String home() {
        return "Hello Secure File Transfer API is Working!";
    }
}