package com.baedalping.gateway.security;

import com.baedalping.gateway.domain.UserAuthorityResponseDto;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.stereotype.Component;

@Component
@Slf4j(topic = "RedisService")
public class RedisComponent {

  private final CacheManager cacheManager;

  public RedisComponent(CacheManager cacheManager) {
    this.cacheManager = cacheManager;
  }

  public Optional<UserAuthorityResponseDto> getUserAuthorityFromRedis(String email) {
    Cache cache = cacheManager.getCache("roleCache");
    if (cache != null) {
      Cache.ValueWrapper valueWrapper = cache.get(email);
      if (valueWrapper != null) {
        return Optional.of((UserAuthorityResponseDto) valueWrapper.get());
      }
    }
    return Optional.empty(); // 캐시에 값이 없으면 null 반환
  }
}
