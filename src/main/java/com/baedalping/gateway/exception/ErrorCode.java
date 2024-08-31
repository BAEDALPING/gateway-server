package com.baedalping.gateway.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {
  INTERNAL_SERVER_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "서버 내부 에러"),

  NOT_FOUND_USER(HttpStatus.NOT_FOUND, "로그인이 되지않은 유저입니다"),
  NOT_PERMISSION(HttpStatus.FORBIDDEN, "API 접근 권한이 없습니다"),
  NOT_AUTH(HttpStatus.BAD_REQUEST, "인증정보가 없습니다"),
  INVALID_TOKEN(HttpStatus.UNAUTHORIZED, "유효하지 않은 토큰입니다"),
  EXPIRED_TOKEN(HttpStatus.UNAUTHORIZED, "토큰이 만료되었습니다")
  ;

  private final HttpStatus status;
  private final String message;
}
