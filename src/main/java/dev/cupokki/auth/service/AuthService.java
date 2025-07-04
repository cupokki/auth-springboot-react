package dev.cupokki.auth.service;

import dev.cupokki.auth.dto.JwtTokenDto;
import dev.cupokki.auth.dto.PasswordResetRequest;
import dev.cupokki.auth.dto.UserLoginRequest;
import dev.cupokki.auth.dto.UserSignUpRequest;
import dev.cupokki.auth.entity.BlacklistItem;
import dev.cupokki.auth.entity.User;
import dev.cupokki.auth.entity.WhitelistItem;
import dev.cupokki.auth.exception.AuthenticationErrorCode;
import dev.cupokki.auth.exception.AuthenticationException;
import dev.cupokki.auth.jwt.JwtTokenProvider;
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
import java.time.LocalDateTime;
import java.util.Date;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final AccessTokenBlackListRepository accessTokenBlackListRepository;
    private final RefreshTokenWhitelistRepository refreshTokenWhiteListRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;

    @Transactional
    public JwtTokenDto login(UserLoginRequest userLoginRequest) {
        var foundedUser = userRepository.findByUsername(userLoginRequest.username())
                .orElseThrow(() -> new AuthenticationException(AuthenticationErrorCode.INVALID_CREDENTIALS));

        if (!passwordEncoder.matches(userLoginRequest.password(), foundedUser.getPassword())) {
            throw new AuthenticationException(AuthenticationErrorCode.INVALID_CREDENTIALS);
        }
        var jwtTokenDto = jwtTokenProvider.createToken(foundedUser.getId(), userLoginRequest.isLongTerm());

        var claims = jwtTokenProvider.extractClaims(jwtTokenDto.refreshToken());

        refreshTokenWhiteListRepository.save(WhitelistItem.builder()
                .jti(claims.getId())
                .expiredAt(claims.getExpiration())
                .build()
        );

        return jwtTokenDto;
    }

    public void signup(UserSignUpRequest userSignUpRequest) {
        if (userRepository.existsByUsername(userSignUpRequest.username())) {
            throw new AuthenticationException(AuthenticationErrorCode.DUPLICATE_USERNAME);
        }

        if (userRepository.existsByEmail(userSignUpRequest.email())) {
            throw new AuthenticationException(AuthenticationErrorCode.DUPLICATE_EMAIL);
        }

        if (!userSignUpRequest.password().equals(userSignUpRequest.confirmPassword())) {
            throw new AuthenticationException(AuthenticationErrorCode.CONFIRM_PASSWORD_MISMATCH);
        }

        var newUser = User.builder()
                .username(userSignUpRequest.username())
                .password(passwordEncoder.encode(userSignUpRequest.password()))
                .email(userSignUpRequest.email())
                .build();

        userRepository.save(newUser);
    }

    @Transactional
    public void logout(Long userId, String accessToken, String refreshToken) {
        Instant now = Instant.now();
        var refreshTokenClaims = jwtTokenProvider.extractClaims(refreshToken);
        var accessTokenClaims = jwtTokenProvider.extractClaims(accessToken);

        refreshTokenWhiteListRepository.deleteById(refreshTokenClaims.getId());
        accessTokenBlackListRepository.save(BlacklistItem.builder() // jpa 아니므로 예외처리 필요
                .jti(accessTokenClaims.getId())
                .ttl(Duration.between(now, accessTokenClaims.getExpiration().toInstant()).getSeconds())
                .build());


    }

    @Transactional
    public JwtTokenDto reissue(String refreshToken) {
        var refreshTokenClaims = jwtTokenProvider.extractClaims(refreshToken);
        var refreshTokenId = refreshTokenClaims.getId();
        var userId = Long.parseLong(refreshTokenClaims.getSubject());
        var whitelistItem= refreshTokenWhiteListRepository.findById(refreshTokenId)
                .orElseThrow(() -> new AuthenticationException(AuthenticationErrorCode.EXPIRED_TOKEN));

        if (whitelistItem.getExpiredAt().before(new Date())) {
            throw new AuthenticationException(AuthenticationErrorCode.EXPIRED_TOKEN);
        }

        refreshTokenWhiteListRepository.delete(whitelistItem);
        var jwtTokenDto = jwtTokenProvider.createToken(userId, false);
        var claims = jwtTokenProvider.extractClaims(jwtTokenDto.refreshToken());
        var now = Instant.now();
        refreshTokenWhiteListRepository.save(WhitelistItem.builder()
                .jti(claims.getId())
                .expiredAt(claims.getExpiration())
                .build()
        );

        // 만료처리 안해도 되는가? 계속 리이슈하면 토큰 무제한 발급가능해진다. -> 그냥 409처리하는게 더 옮은 방향이라 생각된다.
//        var accessTokenClaims = jwtTokenProvider.extractClaims(accessToken);
//        accessTokenBlackListRepository.save(BlacklistItem.builder() // 기존 엑세스 토큰 만료, 실패 예외 필요
//                .jti(accessTokenClaims.getId())
//                .ttl(Duration.between(now, accessTokenClaims.getExpiration().toInstant()).getSeconds())
//                .build()
//        );

        return jwtTokenDto;
    }

    public void checkEmailUniqueness(String email) {
        if (userRepository.existsByEmail(email)) {
            throw new AuthenticationException(AuthenticationErrorCode.DUPLICATE_EMAIL);
        }
    }

    public void checkUsernameUniqueness(String username) {
        if (userRepository.existsByEmail(username)) {
            throw new AuthenticationException(AuthenticationErrorCode.DUPLICATE_USERNAME);
        }
    }

    public void resetPassword(PasswordResetRequest passwordResetRequest) {

    }

    public void findUsername(String email) {
        var FoundUser = userRepository.findByEmail(passwordEncoder.encode(email))
                .orElseThrow(() -> new AuthenticationException(AuthenticationErrorCode.DUPLICATE_USERNAME));
    }
}
