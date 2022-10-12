package com.akmal.oauth2authorizationserver.oauth2.authentication.token;

import com.akmal.oauth2authorizationserver.model.client.GrantType;
import java.security.Principal;
import java.util.List;
import org.springframework.security.core.Authentication;

/**
 * Represents base authentication that contains subject information, authentication state,
 * granted scopes and client information.
 */
public abstract class OAuth2TokenRequestAuthentication implements Authentication {

  private final GrantType grantType;
  private final String clientId;
  private boolean authenticated;
  private String sub;
  private List<String> grantedScopes;

  public OAuth2TokenRequestAuthentication(GrantType grantType, String clientId) {
    this.grantType = grantType;
    this.clientId = clientId;
  }

  @Override
  public Object getDetails() {
    return null;
  }

  @Override
  public Object getPrincipal() {
    return new Principal() {
      @Override
      public String getName() {
        return sub;
      }
    };
  }

  @Override
  public boolean isAuthenticated() {
    return authenticated;
  }

  @Override
  public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
    this.authenticated = isAuthenticated;
  }

  /**
   * If the request is not authenticated it will return null. Otherwise, appropriate provider
   * will set the value to the subject
   * @return
   */
  @Override
  public String getName() {
    return this.sub;
  }


  public GrantType getGrantType() {
    return grantType;
  }


  public String getClientId() {
    return clientId;
  }

  public List<String> getGrantedScopes() {
    return grantedScopes;
  }

  public String getSub() {
    return sub;
  }

  public void setSub(String sub) {
    this.sub = sub;
  }

  public void setGrantedScopes(List<String> grantedScopes) {
    this.grantedScopes = grantedScopes;
  }
}
