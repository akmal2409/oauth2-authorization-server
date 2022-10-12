package com.akmal.oauth2authorizationserver.oauth2.authentication.token;

import com.akmal.oauth2authorizationserver.model.client.GrantType;
import java.util.Collection;
import java.util.List;
import org.springframework.security.core.GrantedAuthority;

public class AuthorizationCodeTokenRequestAuthentication extends
    OAuth2TokenRequestAuthentication {
  private final String code;
  private final String codeVerifier;
  private final String redirectUri;


  public AuthorizationCodeTokenRequestAuthentication(String clientId, String code,
      String codeVerifier, String redirectUri) {
    super(GrantType.AUTHORIZATION_CODE_PKCE, clientId);
    this.code = code;
    this.codeVerifier = codeVerifier;
    this.redirectUri = redirectUri;
  }

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return List.of();
  }

  @Override
  public Object getCredentials() {
    return this.code;
  }

  public String getCode() {
    return code;
  }

  public String getCodeVerifier() {
    return codeVerifier;
  }

  public String getRedirectUri() {
    return redirectUri;
  }
}
