package com.akmal.oauth2authorizationserver.internal.security.authentication;

import java.security.Principal;
import java.util.Collection;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

public class SessionCookieAuthentication implements Authentication {
  private final Collection<? extends GrantedAuthority> authorities;
  private final String sessionId;
  private final String sub;
  private boolean authenticated;
  private Object details;

  public SessionCookieAuthentication(Collection<? extends GrantedAuthority> authorities,
      String sessionId, String sub, boolean authenticated) {
    this.authorities = authorities;
    this.sessionId = sessionId;
    this.sub = sub;
    this.authenticated = authenticated;
  }

  public SessionCookieAuthentication(Collection<? extends GrantedAuthority> authorities,
      String sessionId, String sub, boolean authenticated, Object details) {
    this.authorities = authorities;
    this.sessionId = sessionId;
    this.sub = sub;
    this.authenticated = authenticated;
    this.details = details;
  }

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return this.authorities;
  }

  @Override
  public Object getCredentials() {
    return this.sessionId;
  }

  @Override
  public Object getDetails() {
    return this.details;
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
    return this.authenticated;
  }

  @Override
  public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
    this.authenticated = isAuthenticated;
  }

  @Override
  public String getName() {
    return this.sub;
  }
}
