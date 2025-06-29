package dev.cupokki.auth.repository;

import dev.cupokki.auth.entity.BlacklistItem;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AccessTokenBlackListRepository extends CrudRepository<BlacklistItem, String> {
}
