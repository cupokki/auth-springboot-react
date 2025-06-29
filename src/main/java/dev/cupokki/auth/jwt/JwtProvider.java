package dev.cupokki.auth.jwt;

import dev.cupokki.auth.dto.JwtTokenDto;
import dev.cupokki.auth.exception.AuthenticationErrorCode;
import dev.cupokki.auth.exception.AuthenticationException;
import dev.cupokki.auth.service.CustomUserDetailsService;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class JwtProvider {

    private final String KEY = "121231245512351253241231212312455123512532412312123124551235125324123";
    private final Long ACCESS_TOKEN_EXPIRATION = 60 * 15L; // 초
    private final Long REFRESH_TOKEN_EXPIRATION = 60 * 15L;
    private final Long REFRESH_TOKEN_LONG_EXPIRATION = 60 * 15L;
    private final CustomUserDetailsService customUserDetailsService;

    public JwtTokenDto createToken(Long userId, boolean isLongTerm) {
        var accessToken = Jwts.builder()
                .setId(UUID.randomUUID().toString())
                .setExpiration(
                        Date.from(Instant.now().plusSeconds(ACCESS_TOKEN_EXPIRATION))
                )
                .setSubject(userId.toString())
                .signWith(SignatureAlgorithm.HS256, KEY) // 서명도 필요해요!
                .compact();

        var refreshToken = Jwts.builder()
                .setId(UUID.randomUUID().toString())
                .setExpiration(
                        Date.from(Instant.now().plusSeconds(isLongTerm ?
                                REFRESH_TOKEN_LONG_EXPIRATION :
                                REFRESH_TOKEN_EXPIRATION))
                )
                .setSubject(userId.toString())
                .signWith(SignatureAlgorithm.HS256, KEY) // 서명도 필요해요!
                .compact();

        return new JwtTokenDto(accessToken, refreshToken);
    }

    public UserDetails getAuthentication(String accessToken) {
        try{
            var claims = Jwts.parserBuilder()
                    .setSigningKey(KEY)
                    .build()
                    .parseClaimsJws(accessToken)
                    .getBody();

            var userId = claims.getSubject();

            return customUserDetailsService.loadUserByUsername(userId);
        } catch (SignatureException | MalformedJwtException e) {
            throw new AuthenticationException(AuthenticationErrorCode.INVALID_TOKEN_SIGNATURE);
        } catch (ExpiredJwtException e) {
            throw new AuthenticationException(AuthenticationErrorCode.EXPIRED_TOKEN);
        } catch (UnsupportedJwtException e) {
            throw new AuthenticationException(AuthenticationErrorCode.UNSUPPORTED_TOKEN_FORMAT);
        } catch (IllegalArgumentException | UsernameNotFoundException e) {
            throw new AuthenticationException(AuthenticationErrorCode.INVALID_TOKEN_VALUE);
        }

    }
}
