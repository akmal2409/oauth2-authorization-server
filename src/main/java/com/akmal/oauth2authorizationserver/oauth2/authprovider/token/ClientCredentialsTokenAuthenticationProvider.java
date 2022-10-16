package com.akmal.oauth2authorizationserver.oauth2.authprovider.token;

import com.akmal.oauth2authorizationserver.exception.oauth2.OAuth2AuthorizationException;
import com.akmal.oauth2authorizationserver.oauth2.OAuth2Error;
import com.akmal.oauth2authorizationserver.oauth2.authentication.token.ClientCredentialsTokenRequestAuthentication;
import com.akmal.oauth2authorizationserver.oauth2.config.OAuth2ErrorTypes;
import com.akmal.oauth2authorizationserver.repository.client.ClientRepository;
import java.util.List;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;

public class ClientCredentialsTokenAuthenticationProvider implements AuthenticationProvider {
  private final ClientRepository clientRepository;
  private final PasswordEncoder passwordEncoder;

  public ClientCredentialsTokenAuthenticationProvider(ClientRepository clientRepository,
      PasswordEncoder passwordEncoder) {
    this.clientRepository = clientRepository;
    this.passwordEncoder = passwordEncoder;
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    final var auth = (ClientCredentialsTokenRequestAuthentication) authentication;

    final var existingClientOptional = this.clientRepository.findById(auth.getClientId());

    if (existingClientOptional.isEmpty()) {
      throwError(OAuth2ErrorTypes.ACCESS_DENIED, "invalid credentials", null, null);
    }

    final var existingClient = existingClientOptional.get();

    if (!this.passwordEncoder.matches(auth.getClientSecret(), existingClient.getClientSecret())) {
      throwError(OAuth2ErrorTypes.ACCESS_DENIED, "invalid credentials", null, null);
    }


    auth.setAuthenticated(true);
    auth.setSub(null);
    auth.setGrantedScopes(List.of());
    return auth;
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return ClientCredentialsTokenRequestAuthentication.class.isAssignableFrom(authentication);
  }

  private void throwError(String error, String description, String errorUri, String state) {
    throw new OAuth2AuthorizationException(new OAuth2Error(error,
        description, errorUri, state));
  }

}
