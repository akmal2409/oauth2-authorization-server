package com.akmal.oauth2authorizationserver.rest.v1.dto.scope;

import com.akmal.oauth2authorizationserver.model.client.Scope;

public record ScopeDto(
    long id,
    String name,
    boolean oidcScope,
    String description
) {

  public static ScopeDto from(Scope scope) {
    return new ScopeDto(scope.getId(), scope.getName(), scope.isOidcScope(), scope.getDescription());
  }
}
