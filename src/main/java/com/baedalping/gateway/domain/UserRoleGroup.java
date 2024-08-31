package com.baedalping.gateway.domain;

import com.baedalping.gateway.exception.DeliveryApplicationException;
import com.baedalping.gateway.exception.ErrorCode;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpMethod;

public enum UserRoleGroup {

  ADMIN_ENDPOINTS("admin", Map.of(
      HttpMethod.GET, Set.of(UserRole.ADMIN),
      HttpMethod.POST, Set.of(UserRole.ADMIN),
      HttpMethod.PUT, Set.of(UserRole.ADMIN),
      HttpMethod.DELETE, Set.of(UserRole.ADMIN)
  )),
  STORE_ENDPOINTS("stores", Map.of(
      HttpMethod.GET, Set.of(UserRole.ADMIN, UserRole.OWNER, UserRole.CUSTOMER),
      HttpMethod.POST, Set.of(UserRole.OWNER),
      HttpMethod.PUT, Set.of(UserRole.OWNER),
      HttpMethod.DELETE, Set.of(UserRole.OWNER, UserRole.ADMIN)
  )),
  STORE_CATEGORY_ENDPOINTS("storeCategories", Map.of(
      HttpMethod.GET, Set.of(UserRole.ADMIN, UserRole.OWNER, UserRole.CUSTOMER),
      HttpMethod.POST, Set.of(UserRole.ADMIN),
      HttpMethod.PUT, Set.of(UserRole.ADMIN),
      HttpMethod.DELETE, Set.of(UserRole.ADMIN)
  )),
  PRODUCT_ENDPOINTS("products", Map.of(
      HttpMethod.GET, Set.of(UserRole.ADMIN, UserRole.OWNER, UserRole.CUSTOMER),
      HttpMethod.POST, Set.of(UserRole.OWNER),
      HttpMethod.PUT, Set.of(UserRole.OWNER),
      HttpMethod.DELETE, Set.of(UserRole.OWNER)
  )),
  PRODUCT_CATEGORY_ENDPOINTS("productCategories", Map.of(
      HttpMethod.GET, Set.of(UserRole.ADMIN, UserRole.OWNER, UserRole.CUSTOMER),
      HttpMethod.POST, Set.of(UserRole.ADMIN),
      HttpMethod.PUT, Set.of(UserRole.ADMIN),
      HttpMethod.DELETE, Set.of(UserRole.ADMIN, UserRole.OWNER)
  )),
  ORDER_ENDPOINT("orders", Map.of(//전체 대상 API
      HttpMethod.GET, Set.of(UserRole.ADMIN, UserRole.OWNER, UserRole.CUSTOMER),
      HttpMethod.POST, Set.of(UserRole.CUSTOMER, UserRole.OWNER),
      HttpMethod.DELETE, Set.of(UserRole.ADMIN, UserRole.OWNER, UserRole.CUSTOMER)
  )),
  OWNER_ORDER_ENDPOINT("owner", Map.of(
      HttpMethod.GET, Set.of(UserRole.ADMIN, UserRole.OWNER, UserRole.CUSTOMER)
  )),
  PAYMENT_ENDPOINT("payments", Map.of(
      HttpMethod.GET, Set.of(UserRole.CUSTOMER),
      HttpMethod.POST, Set.of(UserRole.CUSTOMER, UserRole.OWNER),
      HttpMethod.DELETE, Set.of(UserRole.ADMIN, UserRole.CUSTOMER)
  )),
  CART_ENDPOINT("carts", Map.of(
      HttpMethod.GET, Set.of(UserRole.CUSTOMER),
      HttpMethod.POST, Set.of(UserRole.CUSTOMER),
      HttpMethod.PATCH, Set.of(UserRole.CUSTOMER),
      HttpMethod.DELETE, Set.of(UserRole.CUSTOMER)
  )),
  USERS_ENDPOINT("users", Map.of(
      HttpMethod.GET, Set.of(UserRole.CUSTOMER),
      HttpMethod.POST, Set.of(UserRole.CUSTOMER),
      HttpMethod.PUT, Set.of(UserRole.CUSTOMER),
      HttpMethod.DELETE, Set.of(UserRole.CUSTOMER)
  )),
  AUTH_ENDPOINT("auth", Map.of(
      HttpMethod.POST, Set.of(UserRole.ADMIN, UserRole.OWNER, UserRole.CUSTOMER)
  ));

  private String domain;
  private Map<HttpMethod, Set<UserRole>> methodRoleMap;

  private UserRoleGroup(String domain, Map<HttpMethod, Set<UserRole>> methodRoleMap) {
    this.domain = domain;
    this.methodRoleMap = methodRoleMap;
  }

  public String getDomain() {
    return domain;
  }

  public Map<HttpMethod, Set<UserRole>> getMethodRoleMap() {
    return methodRoleMap;
  }

  public static boolean hasPermission(String uriPath, HttpMethod method, String roleName) {
    // uriPath에 해당하는 UserRoleGroup의 methodRoleMap을 찾음
    var roleMap = findMethodRoleMap(uriPath)
        .orElseThrow(() -> new DeliveryApplicationException(ErrorCode.NOT_PERMISSION));

    // 주어진 method에 대한 role set을 가져오고, roleName에 해당하는 역할이 있는지 확인
    return roleMap.getOrDefault(method, Set.of()).stream()
        .anyMatch(role -> role.name().equals(roleName));
  }

  public static Optional<Map<HttpMethod, Set<UserRole>>> findMethodRoleMap(String uriPath) {
    return Arrays.stream(UserRoleGroup.values())
        .filter(group -> uriPath.equals(group.getDomain())) // 해당 uriPath로 시작하는 userGroup 찾기
        .findFirst() // 첫 번째 일치하는 그룹을 가져옴
        .map(UserRoleGroup::getMethodRoleMap);
  }


  @AllArgsConstructor
  @Getter
  public enum UserRole {
    CUSTOMER(101, "CUSTOMER"),
    OWNER(102, "OWNER"),
    ADMIN(202, "ADMIN");

    private long roleNum;
    private String roleName;
  }
}
