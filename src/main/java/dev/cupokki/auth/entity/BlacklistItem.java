package dev.cupokki.auth.entity;

import lombok.Builder;
import lombok.Getter;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.TimeToLive;

@RedisHash("RevokedJwt")
@Getter
@Builder
public class BlacklistItem {

    @Id
    private String jti;

    @TimeToLive
    private Long ttl;
}
