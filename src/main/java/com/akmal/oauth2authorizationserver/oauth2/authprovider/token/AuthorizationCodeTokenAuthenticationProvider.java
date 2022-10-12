package com.akmal.oauth2authorizationserver.oauth2.authprovider.token;

import com.akmal.oauth2authorizationserver.exception.oauth2.OAuth2AuthorizationException;
import com.akmal.oauth2authorizationserver.model.OAuth2AuthorizationCodePendingRequest;
import com.akmal.oauth2authorizationserver.oauth2.OAuth2Error;
import com.akmal.oauth2authorizationserver.oauth2.authentication.token.AuthorizationCodeTokenRequestAuthentication;
import com.akmal.oauth2authorizationserver.oauth2.config.OAuth2ErrorTypes;
import com.akmal.oauth2authorizationserver.oauth2.model.OAuth2CodeChallengeMethod;
import com.akmal.oauth2authorizationserver.repository.OAuth2AuthCodePendingRequestRepository;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;


@RequiredArgsConstructor
public class AuthorizationCodeTokenAuthenticationProvider implements AuthenticationProvider {

  private final OAuth2AuthCodePendingRequestRepository pendingRequestRepository;

  @Transactional
  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    final var auth = (AuthorizationCodeTokenRequestAuthentication) authentication;

    Optional<OAuth2AuthorizationCodePendingRequest> requestOptional = this.pendingRequestRepository.findById(
        auth.getCode());

    if (requestOptional.isEmpty()) {
      throwError(OAuth2ErrorTypes.ACCESS_DENIED, "invalid code", null, null);
    }
    OAuth2AuthorizationCodePendingRequest request = requestOptional.get();

    if (!request.getClientId().equals(auth.getClientId())) {
      throwError(OAuth2ErrorTypes.ACCESS_DENIED, "no session for this client_id", null, null);
    }

    if (Instant.now().isAfter(request.getExpiresAt())) {
      throwError(OAuth2ErrorTypes.ACCESS_DENIED, "invalid code", null, null);
    }

    if (!request.getRedirectUri().equals(auth.getRedirectUri())) {
      throwError(OAuth2ErrorTypes.ACCESS_DENIED, "redirect_uri does not match", null, null);
    }

    if (!this.isCodeVerifierValid(
        auth.getCodeVerifier(), request.getCodeChallenge(), request.getCodeChallengeMethod())) {
      throwError(OAuth2ErrorTypes.ACCESS_DENIED, "code_challenge verification failed", null, null);
    }

    auth.setAuthenticated(true);
    auth.setSub(request.getSub());
    auth.setGrantedScopes(request.getScopes());

    this.pendingRequestRepository.delete(request);

    return auth;
  }

  private boolean isCodeVerifierValid(String codeVerifier, String codeChallenge, OAuth2CodeChallengeMethod algorithm) {
    if (algorithm == null || !StringUtils.hasText(codeVerifier)) return false;

    try {
      MessageDigest digest = MessageDigest.getInstance(algorithm.getName());
      byte[] encodedHash = digest.digest(codeVerifier.getBytes(StandardCharsets.UTF_8));
      String base64Hash = Base64.getUrlEncoder().withoutPadding().encodeToString(encodedHash);

      return base64Hash.equals(codeChallenge);
    } catch (Exception e) {
      return false;
    }
  }


  private void throwError(String error, String description, String errorUri, String state) {
    throw new OAuth2AuthorizationException(new OAuth2Error(error,
        description, errorUri, state));
  }


  @Override
  public boolean supports(Class<?> authentication) {
    return AuthorizationCodeTokenRequestAuthentication.class.isAssignableFrom(authentication);
  }
}
