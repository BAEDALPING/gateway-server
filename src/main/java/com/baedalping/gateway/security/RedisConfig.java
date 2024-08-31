package com.baedalping.gateway.security;

import java.time.Duration;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.cache.CacheKeyPrefix;
import org.springframework.data.redis.cache.RedisCacheConfiguration;
import org.springframework.data.redis.cache.RedisCacheManager;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.serializer.RedisSerializationContext;
import org.springframework.data.redis.serializer.RedisSerializer;

@Configuration
@EnableCaching
public class RedisConfig {

  @Bean
  public RedisCacheManager cacheManager(RedisConnectionFactory redisConnectionFactory) {
    RedisCacheConfiguration configuration =
        RedisCacheConfiguration.defaultCacheConfig()
            .disableCachingNullValues()
            .entryTtl(Duration.ofHours(1))
            .computePrefixWith(CacheKeyPrefix.simple())
            .serializeValuesWith(
                RedisSerializationContext.SerializationPair.fromSerializer(RedisSerializer.java()));

    return RedisCacheManager.builder(redisConnectionFactory).cacheDefaults(configuration).build();
  }
}
