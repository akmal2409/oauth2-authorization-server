package com.akmal.oauth2authorizationserver.oauth2.config;

import java.util.List;
import java.util.Set;

public class OidcScopes {

  private OidcScopes() {}

  public static final String OPENID = "openid";
  public static final String PROFILE = "profile";
  public static final String EMAIL = "email";
  public static final String ADDRESS = "address";
  public static final String PHONE = "phone";
  public static final String OFFLINE_ACCESS = "offline_access";

  public static final Set<String> OIDC_SCOPE_SET = Set.copyOf(
      List.of(OPENID, PROFILE, EMAIL, ADDRESS, PHONE, OFFLINE_ACCESS));
}
