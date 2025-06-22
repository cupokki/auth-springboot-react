package dev.cupokki.auth.dto;

import lombok.Builder;

@Builder
public record JwtTokenDto(String accessToken, String refreshToken) {
}
