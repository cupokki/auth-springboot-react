package dev.cupokki.auth.service;

import dev.cupokki.auth.dto.JwtTokenDto;
import dev.cupokki.auth.dto.UserLoginRequest;
import dev.cupokki.auth.dto.UserSignUpRequest;
import dev.cupokki.auth.entity.RevokedJwt;
import dev.cupokki.auth.entity.User;
import dev.cupokki.auth.exception.AuthenticationErrorCode;
import dev.cupokki.auth.exception.AuthenticationException;
import dev.cupokki.auth.jwt.JwtProvider;
import dev.cupokki.auth.repository.AccessTokenBlackListRepository;
import dev.cupokki.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final AccessTokenBlackListRepository accessTokenBlackListRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;

    public JwtTokenDto login(UserLoginRequest userLoginRequest) {
        var foundedUser = userRepository.findByEmail(userLoginRequest.email())
                .orElseThrow(() -> new AuthenticationException(AuthenticationErrorCode.INVALID_CREDENTIALS));

        if (!passwordEncoder.matches(userLoginRequest.password(), foundedUser.getPassword())) {
            throw new AuthenticationException(AuthenticationErrorCode.INVALID_CREDENTIALS);
        }

        return jwtProvider.createToken(foundedUser.getId(), userLoginRequest.isLongTerm());
    }

    public void signup(UserSignUpRequest userSignUpRequest) {
        if (userRepository.existsByEmail(userSignUpRequest.email())) {
            throw new AuthenticationException(AuthenticationErrorCode.DUPLICATE_EMAIL);
        }

        if (!userSignUpRequest.password().equals(userSignUpRequest.confirmPassword())) {
            throw new AuthenticationException(AuthenticationErrorCode.CONFIRM_PASSWORD_MISMATCH);
        }

        var newUser = User.builder()
                .email(userSignUpRequest.email())
                .username(userSignUpRequest.username())
                .password(passwordEncoder.encode(userSignUpRequest.password()))
                .build();

        userRepository.save(newUser);
    }

    @Transactional
    public void logout(Long userId, String accessToken, String refreshToken) {
        Instant now = Instant.now();
        var accessTokenClaims = jwtProvider.extractClaims(accessToken);
        var refreshTokenClaims = jwtProvider.extractClaims(refreshToken);
        accessTokenBlackListRepository.save(RevokedJwt.builder()
                .jti(accessTokenClaims.getId())
                .ttl(Duration.between(now, accessTokenClaims.getExpiration().toInstant()).getSeconds())
                .build());
        accessTokenBlackListRepository.save(RevokedJwt.builder()
                .jti(refreshTokenClaims.getId())
                .ttl(Duration.between(now, refreshTokenClaims.getExpiration().toInstant()).getSeconds())
                .build());
    }
}
