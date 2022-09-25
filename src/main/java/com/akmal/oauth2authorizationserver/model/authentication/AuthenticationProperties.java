package com.akmal.oauth2authorizationserver.model.authentication;

import java.time.Instant;
import java.util.List;

public record AuthenticationProperties(
    String clientId,
    String redirectUri,
    AuthResponseType responseType,
    String state,
    String codeChallenge,
    CodeChallengeMethod codeChallengeMethod,
    String nonce,
    String idp,
    List<String> idpScopes,
    List<String> scopes
) {


  public AuthenticationTransaction toTransaction() {
    return new AuthenticationTransaction(
        null,
        this.clientId,
        this.redirectUri,
        this.responseType,
        this.state,
        this.codeChallenge,
        this.codeChallengeMethod,
        this.nonce,
        this.idp,
        this.idpScopes,
        this.scopes,
        Instant.now()
    );
  }
}
