package com.akmal.oauth2authorizationserver.model.client;

import org.springframework.util.StringUtils;

public enum GrantType {
  AUTHORIZATION_CODE_PKCE, REFRESH_TOKEN, CLIENT_CREDENTIALS, HYBRID, DEVICE_CODE;

  public static GrantType from(String name) {
    if ("authorization_code".equalsIgnoreCase(name)) return AUTHORIZATION_CODE_PKCE;
    for (GrantType grant: values()) {
      if (grant.name().equalsIgnoreCase(name)) return grant;
    }

    return null;
  }
}
