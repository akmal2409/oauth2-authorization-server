package com.akmal.oauth2authorizationserver.service.v1.client;

import com.akmal.oauth2authorizationserver.exception.persistence.DataNotFoundException;
import com.akmal.oauth2authorizationserver.exception.validation.InvalidScopeConfigurationException;
import com.akmal.oauth2authorizationserver.idgen.Generator;
import com.akmal.oauth2authorizationserver.model.client.Client;
import com.akmal.oauth2authorizationserver.model.client.Grant;
import com.akmal.oauth2authorizationserver.model.client.GrantType;
import com.akmal.oauth2authorizationserver.repository.ScopeRepository;
import com.akmal.oauth2authorizationserver.repository.client.ClientRepository;
import com.akmal.oauth2authorizationserver.repository.client.GrantRepository;
import com.akmal.oauth2authorizationserver.rest.v1.dto.client.ClientDto;
import com.akmal.oauth2authorizationserver.rest.v1.dto.client.SecretGenerationResponse;
import com.akmal.oauth2authorizationserver.rest.v1.dto.client.action.ClientCreateAction;
import com.akmal.oauth2authorizationserver.rest.v1.dto.client.action.ClientUpdateAction;
import com.akmal.oauth2authorizationserver.shared.persistence.TransactionPropagator;
import com.akmal.oauth2authorizationserver.validator.Validator;
import com.akmal.oauth2authorizationserver.validator.client.ClientProperties;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class ClientService {

  private final ClientRepository clientRepository;
  @Qualifier("idGenerator")
  private final Generator<String> idGenerator;
  @Qualifier("secretGenerator")
  private final Generator<String> secretGenerator;
  private final GrantRepository grantRepository;
  private final ScopeRepository scopeRepository;


  private final TransactionPropagator transactionPropagator;
  private final PasswordEncoder passwordEncoder;
  private final Validator<ClientProperties> clientValidator;


  @Transactional(readOnly = true)
  public List<ClientDto> findAllClients() {
    return this.clientRepository
               .findAll()
               .stream()
               .map(ClientDto::from)
               .toList();
  }

  public Optional<ClientDto> findById(@NotNull String clientId) {
    return this.clientRepository.findById(clientId)
               .map(ClientDto::from);
  }

  /**
   * Validates the client creation request by validating all the collections of urls such as:
   * {@link ClientCreateAction#signInRedirectUris()},
   * {@link ClientCreateAction#signOutRedirectUris()} and
   * {@link ClientCreateAction#trustedOrigins()}.
   * <p>
   * It also generates a unique shortened UUID and saves the client. Note: the client secret is not
   * generated at this stage!
   *
   * @param createAction {@link ClientCreateAction} instance
   * @return {@link ClientDto} persisted instance.
   */
  @Transactional
  public ClientDto create(@NotNull ClientCreateAction createAction) {
    Collection<String> availableGrants = grantRepository.findAll().stream().map(Grant::getType).map(
        GrantType::toString).toList();

    this.transactionPropagator
        .withinCurrent(() -> this.clientValidator
                                 .validate(ClientProperties.from(createAction, availableGrants)));

    final var clientId = this.idGenerator.next();
    final var client = createAction.toClient()
                           .withAllowedScopes(
                               new HashSet<>(this.scopeRepository.findAllOidcScopes()))
                           .withClientId(clientId)
                           .withNewEntity(true);

    final var savedClient = this.clientRepository.save(client);
    return ClientDto.from(savedClient);
  }

  /**
   * Updates the existing client with the values passed in the {@link ClientUpdateAction} DTO
   * instance. Firstly, it validates the fields set on the DTO instance, whether they conform to
   * invariants. Thereafter, it validates the presence of the existing client, if not
   * {@link DataNotFoundException} is thrown. Lastly, it updates the properties and saves the client
   * instance.
   *
   * @param clientId           client id
   * @param clientUpdateAction {@link ClientUpdateAction} instance
   * @return {@link ClientDto}
   */
  @Transactional
  public ClientDto update(@NotNull String clientId,
      @NotNull ClientUpdateAction clientUpdateAction) {
    Collection<String> availableGrants = grantRepository.findAll().stream().map(Grant::getType).map(
        GrantType::toString).toList();

    this.transactionPropagator
        .withinCurrent(() -> this.clientValidator
                                 .validate(
                                     ClientProperties.from(clientUpdateAction, availableGrants)));
    final var existingClient = this.clientRepository.findById(clientId)
                                   .orElseThrow(
                                       () -> new DataNotFoundException("Client", clientId));

    final var updatedClient = clientUpdateAction.toClient()
                                  .withClientSecret(existingClient.getClientSecret())
                                  .withClientId(existingClient.getClientId())
                                  .withNewEntity(false);

    final var savedClient = this.clientRepository.save(updatedClient);

    return ClientDto.from(savedClient);
  }

  /**
   * Deletes the client by id.
   *
   * @param clientId id of the {@link Client}
   */
  public void deleteById(String clientId) {
    this.clientRepository.deleteById(clientId);
  }

  /**
   * Generates a clientSecret and returns to the user for one time look up to save it. Afterwards,
   * there is no way to access the client secret because its value is hashed and stored in the
   * database.
   *
   * @param clientId
   * @return
   */
  @Transactional
  public SecretGenerationResponse generateSecret(@NotNull String clientId) {
    final var existingClient = this.clientRepository.findById(clientId)
                                   .orElseThrow(
                                       () -> new DataNotFoundException("client", clientId, null));

    final var secret = this.secretGenerator.next();
    final var hashedSecret = this.passwordEncoder.encode(secret);

    final var updatedClient = existingClient.withClientSecret(hashedSecret);
    this.clientRepository.save(updatedClient);

    return new SecretGenerationResponse(clientId, secret);
  }

  @Transactional
  public void allowScopeForClient(String clientId, int scopeId) {
    final var existingClient = this.clientRepository.findById(clientId)
                                   .orElseThrow(
                                       () -> new DataNotFoundException("client", clientId));
    final var existingScope = this.scopeRepository.findById(scopeId)
                                  .orElseThrow(() -> new DataNotFoundException("scope",
                                      String.valueOf(scopeId)));

    existingClient.getAllowedScopes().add(existingScope);
    this.clientRepository.save(existingClient);
  }

  @Transactional
  public void deleteScopeForClient(String clientId, int scopeId) {
    if (scopeRepository.isOidcScopeById(scopeId)) {
      throw new InvalidScopeConfigurationException("Custom scope", "OIDC reserved scope");
    }

    this.clientRepository.deleteScopeByClientIdAndScopeId(clientId, scopeId);
  }
}
