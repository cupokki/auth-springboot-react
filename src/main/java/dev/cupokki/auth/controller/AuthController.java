package dev.cupokki.auth.controller;

import dev.cupokki.auth.entity.User;
import jakarta.annotation.security.PermitAll;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class AuthController {

    @GetMapping("/auth/health")
    public ResponseEntity<?> health() {
        return ResponseEntity.ok("ok");
    }

    @PostMapping("/login")
    public ResponseEntity<?> login() {
        return ResponseEntity.ok(null);
    }

    @PostMapping("/signup")
    public ResponseEntity<?> signup() {
        return ResponseEntity.ok(null);
    }

    @PermitAll
    @PostMapping("/logout")
    public ResponseEntity<?> logout(
            @AuthenticationPrincipal User user
    ) {
        return ResponseEntity.ok(null);
    }

    @PermitAll
    @PostMapping("/reissue")
    public ResponseEntity<?> reissue(
            @AuthenticationPrincipal User user
    ) {
        return ResponseEntity.ok(null);
    }
}
