package dev.cupokki.auth.dto;

import lombok.Builder;

@Builder
public record UserSignUpRequest(
        String email,
        String username,
        String password,
        String confirmPassword
) {
}
