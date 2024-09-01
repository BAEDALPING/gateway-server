package com.baedalping.gateway.security;

import com.baedalping.gateway.domain.UserAuthorityResponseDto;
import com.fasterxml.jackson.databind.ObjectMapper;
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
        UserAuthorityResponseDto cachedValue = (UserAuthorityResponseDto) valueWrapper.get();
        log.info("redis role: {}", cachedValue.getRole());
        return Optional.of(cachedValue);
      }
    }
    return Optional.empty();
  }
}
