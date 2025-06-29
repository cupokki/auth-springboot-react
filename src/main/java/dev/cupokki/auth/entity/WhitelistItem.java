package dev.cupokki.auth.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.TimeToLive;

@Entity
@Table(name = "whitelist_items")
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class WhitelistItem {

    @Id
    private String jti;

    private Long ttl;
}
