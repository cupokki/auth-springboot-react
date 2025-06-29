package dev.cupokki.auth.controller;

import dev.cupokki.auth.dto.UserLoginRequest;
import dev.cupokki.auth.dto.UserSignUpRequest;
import dev.cupokki.auth.entity.User;
import dev.cupokki.auth.service.AuthService;
import jakarta.annotation.security.PermitAll;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;

@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;

    @GetMapping("/auth/health")
    public ResponseEntity<?> health() {
        return ResponseEntity.ok("ok");
    }

    @PostMapping("/auth/login")
    public ResponseEntity<?> login(@RequestBody UserLoginRequest userLoginRequest) {
        log.info("hi from controller");
        var jwtTokenDto = authService.login(userLoginRequest);
        var accessTokenCookie = ResponseCookie.from("accessToken", jwtTokenDto.accessToken())
                .httpOnly(true)
                .secure(true)
                .path("/")
                .sameSite("None")
                .maxAge(Duration.ofHours(1))
                .build();
        var refreshTokenCookie = ResponseCookie.from("refreshToken", jwtTokenDto.refreshToken())
                .httpOnly(true)
                .secure(true)
                .path("/")
                .sameSite("None")
                .maxAge(Duration.ofHours(1))
                .build();

        return ResponseEntity
                .ok()
                .header(HttpHeaders.SET_COOKIE, accessTokenCookie.toString())
                .header(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString())
                .build();
    }

    @PostMapping("/auth/signup")
    public ResponseEntity<?> signup(@RequestBody UserSignUpRequest userSignUpRequest) {
        authService.signup(userSignUpRequest);
        return ResponseEntity.ok(null);
    }

    @PermitAll
    @PostMapping("/auth/logout")
    public ResponseEntity<?> logout(
            @AuthenticationPrincipal User user,
            @CookieValue("accessToken") String accessToken,
            @CookieValue("refreshToken") String refreshToken
    ) {
        authService.logout(user.getId(), accessToken, refreshToken);
        var accessTokenCookie = ResponseCookie.from("accessToken", accessToken)
                .httpOnly(true)
                .secure(true)
                .path("/")
                .sameSite("None")
                .maxAge(0)
                .build();
        var refreshTokenCookie = ResponseCookie.from("refreshToken", refreshToken)
                .httpOnly(true)
                .secure(true)
                .path("/")
                .sameSite("None")
                .maxAge(0)
                .build();

        return ResponseEntity
                .ok()
                .header(HttpHeaders.SET_COOKIE, accessTokenCookie.toString())
                .header(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString())
                .build();
    }

    @PermitAll
    @PostMapping("/auth/reissue")
    public ResponseEntity<?> reissue(
            @AuthenticationPrincipal User user
    ) {
        return ResponseEntity.ok(null);
    }
}
