package com.baedalping.gateway.filter;

import static com.baedalping.gateway.domain.UserRoleGroup.hasPermission;

import com.baedalping.gateway.domain.UserAuthorityResponseDto;
import com.baedalping.gateway.exception.DeliveryApplicationException;
import com.baedalping.gateway.exception.ErrorCode;
import com.baedalping.gateway.security.RedisComponent;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@Slf4j(topic = "UserRoleValidationFilter ")
public class UserRoleValidationFilter implements GlobalFilter, Ordered {

  public static final String AUTH_URI = "auth";
  public static final String AUTHORIZATION_HEADER = "Authorization";
  public static final String BEARER_PREFIX = "Bearer ";
  private final RedisComponent redisComponent;
  @Value("${jwt.secret-key}")
  private String secret;

  public UserRoleValidationFilter(RedisComponent redisComponent) {
    this.redisComponent = redisComponent;
  }

  public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
    String uri = exchange.getRequest().getURI().getPath().split("/")[1];
    HttpMethod method = exchange.getRequest().getMethod();
    log.info("uri : {}", uri);

    // 인증이 필요한 URI 경로인지 확인
    if (uri.equals(AUTH_URI)) {
      return chain.filter(exchange); // 인증이 필요 없는 경우, 다음 필터로 진행
    }

    // 1. JWT 토큰 검증
    String token = resolveToken(exchange.getRequest());
    log.info("{}", token);

    try {
      String email = getSignature(token);
      log.info("User signature: {}", email);

      // 2. 요청 API의 접근 권한과 로그인한 유저의 권한을 가지고 있는 Redis에서 조회한 권한과 동일한지 검증
      UserAuthorityResponseDto userAuthority = redisComponent.getUserAuthorityFromRedis(email)
          .orElseThrow(() -> new DeliveryApplicationException(ErrorCode.NOT_FOUND_USER));

      if (hasPermission(uri, method, userAuthority.getRole())) {
        exchange.getRequest().mutate()
            .header("requestedUserEmail", email)
            .build();
        return chain.filter(exchange); // 필터 체인의 다음 단계로 진행
      } else {
        return Mono.error(new DeliveryApplicationException(ErrorCode.NOT_PERMISSION));
      }
    } catch (Exception e) {
      return Mono.error(e);
    }}

  private String getSignature(String token) {
    try {
      Claims claims =
          Jwts.parserBuilder()
              .setSigningKey(getKey(secret))
              .build()
              .parseClaimsJws(token)
              .getBody();
      return claims.get("email", String.class);
    } catch (ExpiredJwtException e) {
      throw new DeliveryApplicationException(ErrorCode.EXPIRED_TOKEN);
    } catch (SecurityException
             | MalformedJwtException
             | SignatureException
             | UnsupportedJwtException
             | IllegalArgumentException e) {
      throw new DeliveryApplicationException(ErrorCode.INVALID_TOKEN);
    }
  }

  private static Key getKey(String secretKey) {
    byte[] keyByte = secretKey.getBytes(StandardCharsets.UTF_8);
    return Keys.hmacShaKeyFor(keyByte);
  }

  private String resolveToken(ServerHttpRequest request) {
    String token = request.getHeaders().getFirst(AUTHORIZATION_HEADER);
    if (StringUtils.hasText(token) && token.startsWith(BEARER_PREFIX)) {
      return token.split(" ")[1].trim();
    }
    throw new DeliveryApplicationException(ErrorCode.NOT_AUTH);
  }

  @Override
  public int getOrder() {
    return HIGHEST_PRECEDENCE;
  }
}
