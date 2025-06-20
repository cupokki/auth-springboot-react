package dev.cupokki.auth.dto;

public record JwtTokenDto(String accessToken, String refreshToken) {
}
