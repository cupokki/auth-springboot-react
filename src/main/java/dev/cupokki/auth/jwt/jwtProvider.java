package dev.cupokki.auth.jwt;

import dev.cupokki.auth.service.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class jwtProvider {

    private final String KEY = "123";
    private final CustomUserDetailsService customUserDetailsService;

    public void getAuthentication(String accessToken) {

//        customUserDetailsService.loadUserByUsername();
    }
}
