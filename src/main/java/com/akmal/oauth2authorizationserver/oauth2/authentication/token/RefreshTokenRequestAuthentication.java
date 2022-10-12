package com.akmal.oauth2authorizationserver.oauth2.authentication.token;

import com.akmal.oauth2authorizationserver.model.client.GrantType;
import java.util.Collection;
import java.util.List;
import org.springframework.security.core.GrantedAuthority;

public class RefreshTokenRequestAuthentication extends
    OAuth2TokenRequestAuthentication {
  private final String refreshToken;
  private final List<String> scopes;

  public RefreshTokenRequestAuthentication(String clientId,
      String refreshToken, List<String> scopes) {
    super(GrantType.REFRESH_TOKEN, clientId);
    this.refreshToken = refreshToken;
    this.scopes = scopes;
  }

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return List.of();
  }

  @Override
  public Object getCredentials() {
    return refreshToken;
  }

  public String getRefreshToken() {
    return refreshToken;
  }

  public List<String> getScopes() {
    return scopes;
  }
}
