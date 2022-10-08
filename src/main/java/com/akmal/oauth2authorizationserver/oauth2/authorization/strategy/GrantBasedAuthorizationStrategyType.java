package com.akmal.oauth2authorizationserver.oauth2.authorization.strategy;

import com.akmal.oauth2authorizationserver.model.client.GrantType;

public enum GrantBasedAuthorizationStrategyType {
  AUTHORIZATION_CODE("authorizationCodeStrategy");

  private final String value;

  GrantBasedAuthorizationStrategyType(String value) {
    this.value = value;
  }

  public static GrantBasedAuthorizationStrategyType fromGrantType(GrantType grantType) {
    return switch (grantType) {
      case AUTHORIZATION_CODE_PKCE -> AUTHORIZATION_CODE;
      default -> null;
    };
  }

  public String getValue() {
    return value;
  }

  @Override
  public String toString() {
    return this.value;
  }
}
