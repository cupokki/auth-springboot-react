package dev.cupokki.auth.service;

import dev.cupokki.auth.dto.JwtTokenDto;
import dev.cupokki.auth.dto.UserLoginRequest;
import dev.cupokki.auth.dto.UserSignUpRequest;
import dev.cupokki.auth.entity.BlacklistItem;
import dev.cupokki.auth.entity.User;
import dev.cupokki.auth.entity.WhitelistItem;
import dev.cupokki.auth.exception.AuthenticationErrorCode;
import dev.cupokki.auth.exception.AuthenticationException;
import dev.cupokki.auth.jwt.JwtProvider;
import dev.cupokki.auth.repository.AccessTokenBlackListRepository;
import dev.cupokki.auth.repository.RefreshTokenWhitelistRepository;
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
    private final RefreshTokenWhitelistRepository refreshTokenWhiteListRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;

    @Transactional
    public JwtTokenDto login(UserLoginRequest userLoginRequest) {
        var foundedUser = userRepository.findByEmail(userLoginRequest.email())
                .orElseThrow(() -> new AuthenticationException(AuthenticationErrorCode.INVALID_CREDENTIALS));

        if (!passwordEncoder.matches(userLoginRequest.password(), foundedUser.getPassword())) {
            throw new AuthenticationException(AuthenticationErrorCode.INVALID_CREDENTIALS);
        }
        var jwtTokenDto = jwtProvider.createToken(foundedUser.getId(), userLoginRequest.isLongTerm());

        var claims = jwtProvider.extractClaims(jwtTokenDto.refreshToken());

        refreshTokenWhiteListRepository.save(WhitelistItem.builder()
                .jti(claims.getId())
                .ttl(Duration.between(Instant.now(), claims.getExpiration().toInstant()).getSeconds())
                .build()
        );
        return jwtTokenDto;
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

        accessTokenBlackListRepository.save(BlacklistItem.builder()
                .jti(accessTokenClaims.getId())
                .ttl(Duration.between(now, accessTokenClaims.getExpiration().toInstant()).getSeconds())
                .build());

        refreshTokenWhiteListRepository.deleteById(refreshTokenClaims.getId());
    }
}
