package com.akmal.oauth2authorizationserver.oauth2.authentication.token;

import com.akmal.oauth2authorizationserver.model.client.GrantType;
import java.util.Collection;
import org.springframework.security.core.GrantedAuthority;

public class HybridTokenRequestAuthentication extends
    OAuth2TokenRequestAuthentication {
  private final String code;

  public HybridTokenRequestAuthentication(String clientId, String code) {
    super(GrantType.HYBRID, clientId);
    this.code = code;
  }

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return null;
  }

  @Override
  public Object getCredentials() {
    return null;
  }
}
