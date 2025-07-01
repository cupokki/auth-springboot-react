package dev.cupokki.auth.dto;

import lombok.Builder;

@Builder
public record UserLoginRequest(
        String username,
        String password,
        Boolean isLongTerm
) {
}
