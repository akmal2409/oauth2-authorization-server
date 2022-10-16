package com.akmal.oauth2authorizationserver.service.v1;

import com.akmal.oauth2authorizationserver.exception.validation.InvalidScopeConfigurationException;
import com.akmal.oauth2authorizationserver.oauth2.config.OidcScopes;
import com.akmal.oauth2authorizationserver.repository.ScopeRepository;
import com.akmal.oauth2authorizationserver.rest.v1.dto.scope.ScopeCreationRequest;
import com.akmal.oauth2authorizationserver.rest.v1.dto.scope.ScopeDto;
import java.util.Collection;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class ScopeService {

  private final ScopeRepository scopeRepository;

  @Transactional(readOnly = true)
  public Collection<ScopeDto> findAll() {
    return this.scopeRepository.findAll()
               .stream()
               .map(ScopeDto::from)
               .toList();
  }

  @Transactional
  public ScopeDto saveCustomScope(ScopeCreationRequest creationRequest) {
    if (OidcScopes.OIDC_SCOPE_SET.contains(creationRequest.name())) {
      throw new InvalidScopeConfigurationException("Name that is not reserved as OpenID scope", String.format("Name %s is a reserved OIDC scope", creationRequest.name()));
    }

    final var mappedScope = creationRequest.toScope();

    return ScopeDto.from(
        this.scopeRepository.save(mappedScope)
    );
  }

  @Transactional(readOnly = true)
  public Collection<ScopeDto> findAllByClientId(String clientId) {
    return this.scopeRepository.findAllByClientId(clientId)
               .stream().map(ScopeDto::from)
               .toList();
  }
}
