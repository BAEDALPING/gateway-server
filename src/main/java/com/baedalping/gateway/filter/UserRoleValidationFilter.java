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
import org.springframework.http.HttpMethod;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@Slf4j(topic = "UserRoleValidationFilter ")
public class UserRoleValidationFilter implements GlobalFilter {

  public static final String AUTH_URI = "/auth";
  public static final String AUTHORIZATION_HEADER = "Authorization";
  public static final String BEARER_PREFIX = "Bearer ";

  @Value("${jwt.secret-key}")
  private String secret;

  private final RedisComponent redisComponent;

  public UserRoleValidationFilter(RedisComponent redisComponent) {
    this.redisComponent = redisComponent;
  }

  public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
    String uri = exchange.getRequest().getURI().getPath().split("/")[0];
    HttpMethod method = exchange.getRequest().getMethod();

    // 인증이 필요한 URI 경로인지 확인
    if (uri.equals(AUTH_URI)) {
      return chain.filter(exchange); // 인증이 필요 없는 경우, 다음 필터로 진행
    }

    // 1. JWT 토큰 검증
    return Mono.justOrEmpty(resolveToken(exchange.getRequest()))
        .flatMap(token -> {
          try {
            String email = getSignature(token);
            log.info("user signature : {}", email);

            // 2. 요청 api의 접근권한과 로그인한 유저의 유저권한을 가지고 있는 redis에서 조회한 권한과 동일한지 검증
            UserAuthorityResponseDto userAuthority = redisComponent.getUserAuthorityFromRedis(email)
                .orElseThrow(() -> new DeliveryApplicationException(
                    ErrorCode.NOT_FOUND_USER));// 로그인한 유저권한에서 찾아올 수 없어 예외 발생

            if (hasPermission(uri, method, userAuthority.getRole())) {
              // 권한이 있는 경우, 헤더 추가 및 필터 체인 통과
              exchange.getResponse().getHeaders().add("requestedUserEmail", email);
              return chain.filter(exchange); // 필터 체인의 다음 단계로 진행
            } else {
              return Mono.error(new DeliveryApplicationException(
                  ErrorCode.NOT_PERMISSION)); // API 접근 권한이 없으면 예외 발생
            }
          } catch (Exception e) {
            return Mono.error(e);
          }
        })
        .switchIfEmpty(
            Mono.error(
                new DeliveryApplicationException(ErrorCode.INVALID_TOKEN))); // 토큰이 없을 경우 에러 처리
  }

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

  public static Key getKey(String secretKey) {
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
}
