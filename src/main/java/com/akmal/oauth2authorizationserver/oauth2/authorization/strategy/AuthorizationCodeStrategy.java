package com.akmal.oauth2authorizationserver.oauth2.authorization.strategy;

import com.akmal.oauth2authorizationserver.model.OAuth2AuthorizationCodePendingRequest;
import com.akmal.oauth2authorizationserver.model.client.Client;
import com.akmal.oauth2authorizationserver.oauth2.authentication.OAuth2WebFlowRequestAuthentication;
import com.akmal.oauth2authorizationserver.repository.OAuth2AuthCodePendingRequestRepository;
import com.akmal.oauth2authorizationserver.shared.persistence.TransactionPropagator;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ThreadLocalRandom;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.util.UriComponentsBuilder;

@RequiredArgsConstructor
public class AuthorizationCodeStrategy implements GrantBasedAuthorizationStrategy {
  private static final long CODE_LIFETIME_MS = 300*1000; // 300s
  private final OAuth2AuthCodePendingRequestRepository repository;
  private final TransactionPropagator transactionPropagator;
  private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

  /**
   * Based on the parsed OAuth2 parameters it saves the request context and generates the code
   * needed for a token exchange. Thereafter, it redirects the client specified in the {@link Client#getSignInRedirectUris()}.
   *
   * Code expiration is set to 300s.
   * @param authentication parsed OAuth2 attributes
   * @param request http request
   * @param response http response
   * @throws IOException
   */
  @Transactional
  @Override
  public void handle(OAuth2WebFlowRequestAuthentication authentication, HttpServletRequest request,
      HttpServletResponse response) throws IOException {
    final var code = transactionPropagator.withinCurrent(this::generateCode);
    // persist the details
    final var authContext = new OAuth2AuthorizationCodePendingRequest(code, authentication.getClientId(),
        authentication.getRedirectUri(), authentication.getCodeChallenge(), authentication.getCodeChallengeMethod(),
        authentication.getScopes(), Instant.now().plus(Duration.ofMillis(CODE_LIFETIME_MS)), authentication.getName(), true);

    this.repository.save(authContext);
    final var redirectUrl = this.transactionPropagator.withinCurrent(() -> this.constructRedirectUrl(code, authentication.getRedirectUri()));

    this.redirectStrategy.sendRedirect(request, response, redirectUrl);
  }

  private String constructRedirectUrl(String code, String redirectUri) {
    return UriComponentsBuilder.fromHttpUrl(redirectUri)
        .queryParam("code", code)
               .toUriString();
  }

  private String generateCode() {
    final byte[] bytes = new byte[4];
    ThreadLocalRandom.current().nextBytes(bytes);
    return new String(Hex.encode(bytes)).toUpperCase();
  }
}
