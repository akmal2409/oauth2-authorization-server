package com.akmal.oauth2authorizationserver.oauth2.authentication;

import java.util.Collection;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

public abstract class AbstractOAuth2Authentication implements Authentication {
  protected final Collection<? extends GrantedAuthority> authorities;
  protected transient Object principal;
  private boolean authenticated;

  protected AbstractOAuth2Authentication(Collection<? extends GrantedAuthority> authorities,
      Object principal, boolean authenticated) {
    this.authorities = authorities;
    this.principal = principal;
    this.authenticated = authenticated;
  }

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return this.authorities;
  }

  @Override
  public Object getPrincipal() {
    return this.principal;
  }

  @Override
  public boolean isAuthenticated() {
    return this.authenticated;
  }

  @Override
  public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
    this.authenticated = isAuthenticated;
  }
}
