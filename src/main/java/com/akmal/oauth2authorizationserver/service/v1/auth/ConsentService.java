package com.akmal.oauth2authorizationserver.service.v1.auth;

import com.akmal.oauth2authorizationserver.exception.oauth2.OAuth2AuthorizationException;
import com.akmal.oauth2authorizationserver.model.client.Client;
import com.akmal.oauth2authorizationserver.model.client.Grant;
import com.akmal.oauth2authorizationserver.model.client.Scope;
import com.akmal.oauth2authorizationserver.model.user.UserGrantedClient;
import com.akmal.oauth2authorizationserver.oauth2.OAuth2Error;
import com.akmal.oauth2authorizationserver.oauth2.authprovider.Tuple;
import com.akmal.oauth2authorizationserver.oauth2.config.OAuth2ErrorTypes;
import com.akmal.oauth2authorizationserver.oauth2.web.model.Consent;
import com.akmal.oauth2authorizationserver.oauth2.web.model.ConsentRequest;
import com.akmal.oauth2authorizationserver.repository.ScopeRepository;
import com.akmal.oauth2authorizationserver.repository.UserGrantedClientRepository;
import com.akmal.oauth2authorizationserver.repository.client.ClientRepository;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class ConsentService {
  private final ClientRepository clientRepository;
  private final UserGrantedClientRepository userGrantedClientRepository;
  private final ScopeRepository scopeRepository;

  @Transactional
  public ConsentRequest findPendingAndGrantedScopesByClientId(String clientId, List<Integer> grantScopeIds) {
    final var client = this.clientRepository.findByIdJoinedWithAllowedScopes(clientId)
                           .orElseThrow(() -> new OAuth2AuthorizationException(new OAuth2Error(
                               OAuth2ErrorTypes.INVALID_REQUEST, "client does not exist", null, null)));
    final var currentUserSub = SecurityContextHolder.getContext().getAuthentication().getName();
    final var userGrantedClient = this.userGrantedClientRepository.findBySubAndClientIdJoinedWithScopes(currentUserSub,
        clientId).orElse(new UserGrantedClient(currentUserSub, clientId, new ArrayList<>()));
    final var requestedScopes = this.scopeRepository.findAllById(grantScopeIds);

    if (!this.areClientRequestedScopesValid(client.getAllowedScopes(), requestedScopes)) {
      throw  new OAuth2AuthorizationException(new OAuth2Error(
          OAuth2ErrorTypes.ACCESS_DENIED, "invalid scopes", null, null));
    }

    final var pendingScopes = new LinkedList<Scope>();
    final var grantedScopeIdSet = userGrantedClient.getGrantedScopes().stream().map(Scope::getId).collect(Collectors.toCollection(
        HashSet::new));

    for (Scope requestedScope: requestedScopes) {
      if (!grantedScopeIdSet.contains(requestedScope.getId())) {
        pendingScopes.add(requestedScope);
        grantedScopeIdSet.add(requestedScope.getId());
      }
    }

    return new ConsentRequest(userGrantedClient.getGrantedScopes(),
        pendingScopes, client.getName(), clientId);
  }

  /**
   * Verifies that all the requested scopes by the client application are actually valid.
   * @param allowedScopes scopes allowed in the client configuration
   * @param requestedScopes scopes requested by the requesting application
   * @return
   */
  private boolean areClientRequestedScopesValid(List<Scope> allowedScopes, List<Scope> requestedScopes) {
    final var allowedScopeSet = new HashSet<>(allowedScopes.stream().map(Scope::getId).toList());

    for (Scope requestedScope: requestedScopes) {
      if (!allowedScopeSet.contains(requestedScope.getId())) {
        return false;
      }
    }

    return true;
  }

  @Transactional
  public void grantScopes(Consent consent) {
    final var client = this.clientRepository.findByIdJoinedWithAllowedScopes(consent.getClientId())
                           .orElseThrow(() -> new OAuth2AuthorizationException(new OAuth2Error(
                               OAuth2ErrorTypes.INVALID_REQUEST, "client does not exist", null, null)));
    final var currentUserSub = SecurityContextHolder.getContext().getAuthentication().getName();
    final var userGrantedClient = this.userGrantedClientRepository.findBySubAndClientIdJoinedWithScopes(currentUserSub,
        consent.getClientId()).orElse(new UserGrantedClient(currentUserSub, consent.getClientId(), new ArrayList<>()));

    if (!this.areClientRequestedScopesValid(client.getAllowedScopes(), consent.getAllowedScopes())) {
      throw  new OAuth2AuthorizationException(new OAuth2Error(
          OAuth2ErrorTypes.ACCESS_DENIED, "invalid scopes", null, null));
    }

    userGrantedClient.getGrantedScopes().addAll(consent.getAllowedScopes());
    this.userGrantedClientRepository.save(userGrantedClient);
  }
}
