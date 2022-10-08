package com.akmal.oauth2authorizationserver.oauth2.authprovider;

import com.akmal.oauth2authorizationserver.exception.oauth2.OAuth2AuthorizationException;
import com.akmal.oauth2authorizationserver.model.client.Grant;
import com.akmal.oauth2authorizationserver.model.client.GrantType;
import com.akmal.oauth2authorizationserver.model.client.Scope;
import com.akmal.oauth2authorizationserver.model.user.UserGrantedClient;
import com.akmal.oauth2authorizationserver.oauth2.OAuth2Error;
import com.akmal.oauth2authorizationserver.oauth2.authentication.OAuth2WebFlowAuthenticationDetails;
import com.akmal.oauth2authorizationserver.oauth2.authentication.OAuth2WebFlowConsentAuthentication;
import com.akmal.oauth2authorizationserver.oauth2.authentication.OAuth2WebFlowRequestAuthentication;
import com.akmal.oauth2authorizationserver.oauth2.config.OAuth2ErrorTypes;
import com.akmal.oauth2authorizationserver.oauth2.config.OAuth2ParameterNames;
import com.akmal.oauth2authorizationserver.oauth2.model.OAuth2ResponseType;
import com.akmal.oauth2authorizationserver.repository.ScopeRepository;
import com.akmal.oauth2authorizationserver.repository.UserGrantedClientRepository;
import com.akmal.oauth2authorizationserver.repository.client.ClientRepository;
import com.akmal.oauth2authorizationserver.shared.persistence.TransactionPropagator;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.transaction.annotation.Transactional;

/**
 * Custom authentication provider that verifies the client configuration, whether the client has
 * been authenticated prior to hitting /authorize endpoint.
 */
public class OAuth2WebFlowRequestAuthenticationProvider implements AuthenticationProvider {

  private final ClientRepository clientRepository;
  private final UserGrantedClientRepository userGrantedClientRepository;
  private final ScopeRepository scopeRepository;
  private final TransactionPropagator transactionPropagator;

  public OAuth2WebFlowRequestAuthenticationProvider(ClientRepository clientRepository,
      UserGrantedClientRepository userGrantedClientRepository, ScopeRepository scopeRepository,
      TransactionPropagator transactionPropagator) {
    this.clientRepository = clientRepository;
    this.userGrantedClientRepository = userGrantedClientRepository;
    this.scopeRepository = scopeRepository;
    this.transactionPropagator = transactionPropagator;
  }

  @Transactional
  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    final OAuth2WebFlowRequestAuthentication webFlowAuth = (OAuth2WebFlowRequestAuthentication) authentication;
    final OAuth2WebFlowAuthenticationDetails context = (OAuth2WebFlowAuthenticationDetails) authentication.getDetails();

    final Authentication internalAuthentication = (Authentication) webFlowAuth.getPrincipal();

    // the client must be fully authenticated before starting the flow.
    if (internalAuthentication == null || !internalAuthentication.isAuthenticated()) {
      return null;
    }

    final var clientOptional = this.clientRepository.findById(webFlowAuth.getClientId());
    final var state = context.request().getParameter(OAuth2ParameterNames.STATE);

    if (clientOptional.isEmpty()) {
      throwError(OAuth2ErrorTypes.ACCESS_DENIED, "Client does not exist", null,
          state);
    }
    final var client = clientOptional.get();

    // now we need to check if the client's responseTypes are allowed according to client configuration
    this.validateResponseTypes(webFlowAuth.getResponseTypes(), client.getGrants(), state);

    // check if redirect URI matches
    if (client.getSignInRedirectUris().stream()
            .noneMatch(url -> url.equals(webFlowAuth.getRedirectUri()))) {
      throwError(OAuth2ErrorTypes.ACCESS_DENIED,
          "Redirect URI is not present in the client configuration", null, state);
    }

    final var clientScopes = client.getAllowedScopes().stream().map(Scope::getName)
                                 .collect(Collectors.toCollection(
                                     HashSet::new));

    for (String requestedScope : webFlowAuth.getScopes()) {
      if (!clientScopes.contains(requestedScope)) {
        throwError(OAuth2ErrorTypes.INVALID_SCOPE,
            String.format("Requested scope %s is invalid", requestedScope),
            "https://www.rfc-editor.org/rfc/rfc6749#section-7.2", state);
      }
    }

    if (!client.isRequireUserConsent()) {
      return new OAuth2WebFlowConsentAuthentication(webFlowAuth,
          false, List.of(), List.of());
    }

    Tuple<List<Scope>, List<Scope>> scopeTuple = this.transactionPropagator.withinCurrent(() -> this.findNotGrantedScopesForUser(
        ((Principal) internalAuthentication.getPrincipal()).getName(),
        client.getClientId(),
        webFlowAuth.getScopes()));

    return new OAuth2WebFlowConsentAuthentication(webFlowAuth,
        client.isRequireUserConsent() && !scopeTuple.getT1().isEmpty(), scopeTuple.getT2(),
        scopeTuple.getT1());
  }

  /**
   * Method finds all granted by the user scopes to a particular client. If the user has not granted
   * any access, then we simply consider all requested scopes for consent page promt. However, if
   * the user has already given a consent to a particular set of scopes, then we must filter out and
   * return only the ones that were not yet granted.
   *
   * @param sub
   * @param clientId
   * @param requestedScopes
   * @return Tuple object containing as the first element not granted scopes and second element as
   * granted scopes.
   */
  private Tuple<List<Scope>, List<Scope>> findNotGrantedScopesForUser(String sub,
      String clientId, List<String> requestedScopes) {
    UserGrantedClient grantedClient = this.userGrantedClientRepository
                                          .findBySubAndClientId(sub, clientId)
                                          .orElse(null);

    Set<String> grantedScopeSet = new HashSet<>(grantedClient == null ?
                                                   List.of() :
                                                   grantedClient.getGrantedScopes().stream().map(Scope::getName).toList());

    if (grantedClient == null || grantedClient.getGrantedScopes().isEmpty()) {
      // then we need to request all scopes
      return new Tuple<>(this.scopeRepository.findAllByNameIsIn(requestedScopes),
          List.of());
    } else {
      List<Scope> requestedScopeList = this.scopeRepository.findAllByNameIsIn(requestedScopes);
      List<Scope> notGrantedScopes = new ArrayList<>();
      for (Scope requestedScope: requestedScopeList) {
        if (!grantedScopeSet.contains(requestedScope.getName())) {
          notGrantedScopes.add(requestedScope);
        }
      }

      return new Tuple<>(notGrantedScopes, new ArrayList<>(grantedClient.getGrantedScopes()));
    }
  }


  private void validateResponseTypes(Collection<OAuth2ResponseType> responseTypes,
      Collection<Grant> clientGrants, String state) {
    Set<GrantType> grantTypes = clientGrants.stream().map(Grant::getType).collect(
        Collectors.toCollection(HashSet::new));

    for (OAuth2ResponseType responseType : responseTypes) {
      if (OAuth2ResponseType.CODE.equals(responseType) &&
              !grantTypes.contains(GrantType.AUTHORIZATION_CODE_PKCE) && !grantTypes.contains(
          GrantType.HYBRID)) {
        throwError(OAuth2ErrorTypes.UNAUTHORIZED_CLIENT,
            "Authorization Code or Hybrid Grants are required for response_type=code", null, state);
      } else if ((OAuth2ResponseType.TOKEN.equals(responseType)
                      || OAuth2ResponseType.ID_TOKEN.equals(responseType)) &&
                     !grantTypes.contains(GrantType.HYBRID)) {
        throwError(OAuth2ErrorTypes.UNAUTHORIZED_CLIENT,
            "Hybrid Grant is required for response_type=token id_token", null, state);
      }
    }
  }


  private void throwError(String error, String description, String errorUri, String state) {
    throw new OAuth2AuthorizationException(new OAuth2Error(error,
        description, errorUri, state));
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return OAuth2WebFlowRequestAuthentication.class.isAssignableFrom(authentication);
  }
}
