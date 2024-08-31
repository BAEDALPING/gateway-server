package com.baedalping.gateway.domain;

import java.io.Serializable;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@Getter
@AllArgsConstructor
public class UserAuthorityResponseDto implements Serializable {

  private String email;
  private String role;
}