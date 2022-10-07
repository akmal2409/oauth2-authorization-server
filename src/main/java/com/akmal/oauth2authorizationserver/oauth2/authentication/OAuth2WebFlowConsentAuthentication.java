package com.akmal.oauth2authorizationserver.oauth2.authentication;

import com.akmal.oauth2authorizationserver.model.client.Scope;
import com.akmal.oauth2authorizationserver.oauth2.model.OAuth2CodeChallengeMethod;
import com.akmal.oauth2authorizationserver.oauth2.model.OAuth2ResponseMode;
import com.akmal.oauth2authorizationserver.oauth2.model.OAuth2ResponseType;
import java.util.Collection;
import java.util.List;
import org.springframework.security.core.GrantedAuthority;

public class OAuth2WebFlowConsentAuthentication extends OAuth2WebFlowRequestAuthentication {
  // TODO: store requested and granted scopes
  private final boolean requiresConsent;
  private final List<Scope> grantedScopes;
  private final List<Scope> notGrantedScopes;

  public OAuth2WebFlowConsentAuthentication(Collection<? extends GrantedAuthority> authorities,
      Object principal, boolean authenticated, String clientId, String redirectUri,
      List<OAuth2ResponseType> responseTypes, String state, String codeChallenge,
      OAuth2CodeChallengeMethod codeChallengeMethod, String nonce, String idp,
      OAuth2ResponseMode responseMode, List<String> idpScopes, List<String> scopes,
      OAuth2WebFlowAuthenticationDetails details, boolean requiresConsent,
      List<Scope> grantedScopes, List<Scope> notGrantedScopes) {
    super(authorities, principal, authenticated, clientId, redirectUri, responseTypes, state,
        codeChallenge, codeChallengeMethod, nonce, idp, responseMode, idpScopes, scopes, details);
    this.requiresConsent = requiresConsent;
    this.grantedScopes = grantedScopes;
    this.notGrantedScopes = notGrantedScopes;
  }

  public OAuth2WebFlowConsentAuthentication(OAuth2WebFlowRequestAuthentication authentication,
      boolean requiresConsent, List<Scope> grantedScopes, List<Scope> notGrantedScopes) {
    this(authentication.getAuthorities(),
        authentication.getPrincipal(),
        authentication.isAuthenticated(),
        authentication.getClientId(),
        authentication.getRedirectUri(),
        authentication.getResponseTypes(),
        authentication.getState(),
        authentication.getCodeChallenge(),
        authentication.getCodeChallengeMethod(),
        authentication.getNonce(),
        authentication.getIdp(),
        authentication.getResponseMode(),
        authentication.getIdpScopes(),
        authentication.getScopes(),
        (OAuth2WebFlowAuthenticationDetails) authentication.getDetails(),
        requiresConsent, grantedScopes, notGrantedScopes);
  }

  public  boolean requiresConsent() {
    return this.requiresConsent && !this.notGrantedScopes.isEmpty();
  }

  public List<Scope> getGrantedScopes() {
    return grantedScopes;
  }

  public List<Scope> getNotGrantedScopes() {
    return notGrantedScopes;
  }
}
