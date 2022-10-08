package com.akmal.oauth2authorizationserver.oauth2.authentication;

import com.akmal.oauth2authorizationserver.oauth2.model.OAuth2CodeChallengeMethod;
import com.akmal.oauth2authorizationserver.oauth2.model.OAuth2ResponseMode;
import com.akmal.oauth2authorizationserver.oauth2.model.OAuth2ResponseType;
import java.util.Collection;
import java.util.List;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

/**
 * The class represents the authentication interface implementation that contains
 * OAuth2 request specific parameters that are required during browser authentication.
 * Holds information about clientId, redirect_uri etc, needed for filters down the stream
 * to complete the flow.
 */
public class OAuth2WebFlowRequestAuthentication extends AbstractOAuth2Authentication {
  private final String clientId;
  private final String redirectUri;
  private final List<OAuth2ResponseType> responseTypes;
  private final String state;
  private final String codeChallenge;
  private final OAuth2CodeChallengeMethod codeChallengeMethod;
  private final String nonce;
  private final String idp;
  private final OAuth2ResponseMode responseMode;
  private final List<String> idpScopes;
  private final List<String> scopes;
  private final OAuth2WebFlowAuthenticationDetails details;

  public OAuth2WebFlowRequestAuthentication(Collection<? extends GrantedAuthority> authorities,
      Object principal, boolean authenticated, String clientId, String redirectUri,
      List<OAuth2ResponseType> responseTypes, String state, String codeChallenge,
      OAuth2CodeChallengeMethod codeChallengeMethod, String nonce, String idp,
      OAuth2ResponseMode responseMode, List<String> idpScopes, List<String> scopes,  OAuth2WebFlowAuthenticationDetails details) {
    super(authorities, principal, authenticated);
    this.clientId = clientId;
    this.redirectUri = redirectUri;
    this.responseTypes = responseTypes;
    this.state = state;
    this.codeChallenge = codeChallenge;
    this.codeChallengeMethod = codeChallengeMethod;
    this.nonce = nonce;
    this.idp = idp;
    this.responseMode = responseMode;
    this.idpScopes = idpScopes;
    this.scopes = scopes;
    this.details = details;
  }

  /**
   * Returns authentication object that is set by the authorization filter, which
   * extracts and verifies the login information (session) of the user.
   * @return {@link org.springframework.security.core.Authentication}
   */
  @Override
  public Object getCredentials() {
    return null;
  }

  @Override
  public Object getDetails() {
    return this.details;
  }

  @Override
  public String getName() {
    return this.principal != null ? ((Authentication) this.principal).getName() : null;
  }

  public String getClientId() {
    return clientId;
  }

  public String getRedirectUri() {
    return redirectUri;
  }

  public List<OAuth2ResponseType> getResponseTypes() {
    return responseTypes;
  }

  public String getState() {
    return state;
  }

  public String getCodeChallenge() {
    return codeChallenge;
  }

  public OAuth2CodeChallengeMethod getCodeChallengeMethod() {
    return codeChallengeMethod;
  }

  public String getNonce() {
    return nonce;
  }

  public String getIdp() {
    return idp;
  }

  public OAuth2ResponseMode getResponseMode() {
    return responseMode;
  }

  public List<String> getIdpScopes() {
    return idpScopes;
  }

  public List<String> getScopes() {
    return scopes;
  }

  @Override
  public String toString() {
    return "OAuth2WebFlowRequestAuthentication{" +
               "clientId='" + clientId + '\'' +
               ", redirectUri='" + redirectUri + '\'' +
               ", responseTypes=" + responseTypes +
               ", state=[STRIPPED]" +
               ", codeChallenge='[STRIPPED]'" +
               ", codeChallengeMethod=" + codeChallengeMethod +
               ", nonce='[STRIPPED]'" +
               ", idp='" + idp + '\'' +
               ", responseMode=" + responseMode +
               ", idpScopes=" + idpScopes +
               ", scopes=" + scopes +
               '}';
  }
}
