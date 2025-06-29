package dev.cupokki.auth.repository;

import dev.cupokki.auth.entity.WhitelistItem;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RefreshTokenWhitelistRepository extends JpaRepository<WhitelistItem, String> {
}
