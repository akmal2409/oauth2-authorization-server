package com.akmal.oauth2authorizationserver.oauth2.authentication.token;

import com.akmal.oauth2authorizationserver.model.client.GrantType;
import java.util.Collection;
import java.util.List;
import org.springframework.security.core.GrantedAuthority;

public class ClientCredentialsTokenRequestAuthentication extends
    OAuth2TokenRequestAuthentication {

  private final String clientSecret;

  public ClientCredentialsTokenRequestAuthentication(String clientId,
      String clientSecret) {
    super(GrantType.CLIENT_CREDENTIALS, clientId);
    this.clientSecret = clientSecret;
  }

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return List.of();
  }

  @Override
  public Object getCredentials() {
    return this.clientSecret;
  }

  public String getClientSecret() {
    return clientSecret;
  }
}
