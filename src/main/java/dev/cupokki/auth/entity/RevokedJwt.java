package dev.cupokki.auth.entity;

import lombok.Builder;
import lombok.Getter;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.TimeToLive;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@EnableWebSecurity
@RedisHash("RevokedJwt")
@Getter
@Builder
public class RevokedJwt {

    @Id
    private String jti;

    @TimeToLive
    private Long ttl;
}
