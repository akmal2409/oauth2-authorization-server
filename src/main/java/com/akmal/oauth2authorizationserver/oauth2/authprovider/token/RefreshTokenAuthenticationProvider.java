package com.akmal.oauth2authorizationserver.oauth2.authprovider.token;

import com.akmal.oauth2authorizationserver.exception.oauth2.OAuth2AuthorizationException;
import com.akmal.oauth2authorizationserver.oauth2.OAuth2Error;
import com.akmal.oauth2authorizationserver.oauth2.authentication.token.RefreshTokenRequestAuthentication;
import com.akmal.oauth2authorizationserver.oauth2.config.OAuth2ErrorTypes;
import com.akmal.oauth2authorizationserver.repository.RefreshTokenRepository;
import java.time.Instant;
import java.util.HashSet;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class RefreshTokenAuthenticationProvider implements AuthenticationProvider {
  private final RefreshTokenRepository refreshTokenRepository;

  public RefreshTokenAuthenticationProvider(RefreshTokenRepository refreshTokenRepository) {
    this.refreshTokenRepository = refreshTokenRepository;
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    final var auth = (RefreshTokenRequestAuthentication) authentication;

    final var refreshTokenOptional = this.refreshTokenRepository.findByTokenJoinFetchUser(auth.getRefreshToken());

    if (refreshTokenOptional.isEmpty()) {
      throwError(OAuth2ErrorTypes.ACCESS_DENIED, "invalid refresh_token", null, null);
    }
    final var refreshToken = refreshTokenOptional.get();


    if (!refreshToken.getClient().getClientId().equals(auth.getClientId())) {
      throwError(OAuth2ErrorTypes.ACCESS_DENIED, "invalid refresh_token", null, null);
    }

    if (refreshToken.getExpiresAt().isBefore(Instant.now())) {
      throwError(OAuth2ErrorTypes.ACCESS_DENIED, "invalid refresh_token", null, null);
    }

    final var grantedScopeSet = new HashSet<>(refreshToken.getScopes());

    for (String scope: auth.getScopes()) {
      if (!grantedScopeSet.contains(scope)) {
        throwError(OAuth2ErrorTypes.ACCESS_DENIED, "requested scopes must be a subset of the previous ones", null, null);
      }
    }

    this.refreshTokenRepository.delete(refreshToken);

    auth.setSub(refreshToken.getUser().getSub());
    if (auth.getScopes().isEmpty()) {
      auth.setGrantedScopes(refreshToken.getScopes());
    } else {
      auth.setGrantedScopes(auth.getScopes());
    }
    auth.setAuthenticated(true);
    return auth;
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return RefreshTokenRequestAuthentication.class.isAssignableFrom(authentication);
  }

  private void throwError(String error, String description, String errorUri, String state) {
    throw new OAuth2AuthorizationException(new OAuth2Error(error,
        description, errorUri, state));
  }


}
