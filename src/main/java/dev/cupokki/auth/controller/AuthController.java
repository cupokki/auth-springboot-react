package dev.cupokki.auth.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class AuthController {

    @PostMapping("/login")
    public ResponseEntity<?> login() {
        return ResponseEntity.ok(null);
    }

    @PostMapping("/signup")
    public ResponseEntity<?> signup() {
        return ResponseEntity.ok(null);
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout() {
        return ResponseEntity.ok(null);
    }

    @PostMapping("/reissue")
    public ResponseEntity<?> reissue() {
        return ResponseEntity.ok(null);
    }
}
