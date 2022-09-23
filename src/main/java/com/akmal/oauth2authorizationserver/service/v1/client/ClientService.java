package com.akmal.oauth2authorizationserver.service.v1.client;

import com.akmal.oauth2authorizationserver.exception.persistence.DataNotFoundException;
import com.akmal.oauth2authorizationserver.idgen.Generator;
import com.akmal.oauth2authorizationserver.model.client.Client;
import com.akmal.oauth2authorizationserver.model.client.Grant;
import com.akmal.oauth2authorizationserver.model.client.GrantType;
import com.akmal.oauth2authorizationserver.repository.client.ClientRepository;
import com.akmal.oauth2authorizationserver.repository.client.GrantRepository;
import com.akmal.oauth2authorizationserver.rest.v1.dto.client.ClientDto;
import com.akmal.oauth2authorizationserver.rest.v1.dto.client.SecretGenerationResponse;
import com.akmal.oauth2authorizationserver.rest.v1.dto.client.action.ClientCreateAction;
import com.akmal.oauth2authorizationserver.shared.persistence.TransactionPropagator;
import com.akmal.oauth2authorizationserver.validator.Validator;
import com.akmal.oauth2authorizationserver.validator.client.ClientProperties;
import java.util.Collection;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class ClientService {

  private final ClientRepository clientRepository;
  @Qualifier("idGenerator") private final Generator<String> idGenerator;
  @Qualifier("secretGenerator") private final Generator<String> secretGenerator;
  private final GrantRepository grantRepository;

  private final TransactionPropagator transactionPropagator;
  private final PasswordEncoder passwordEncoder;
  private final Validator<ClientProperties> clientValidator;



  @Transactional(readOnly = true)
  public List<ClientDto> findAllClients() {
    List<Client> clients = this.clientRepository
                               .findAll();

    for (Client client: clients) {

      for (Grant grant: client.getGrants()) {
      }
      System.out.println("CLIENT " + client.getGrants().size());
    }
    return this.clientRepository
               .findAll()
               .stream()
               .map(ClientDto::from)
               .toList();
  }

  /**
   * Validates the client creation request by validating all the collections of urls such as:
   * {@link ClientCreateAction#signInRedirectUris()}, {@link ClientCreateAction#signOutRedirectUris()} and
   * {@link ClientCreateAction#trustedOrigins()}.
   *
   * It also generates a unique shortened UUID and saves the client.
   * Note: the client secret is not generated at this stage!
   *
   * @param createAction {@link ClientCreateAction} instance
   * @return {@link ClientDto} persisted instance.
   */
  @Transactional
  public ClientDto create(ClientCreateAction createAction) {
    Collection<String> availableGrants = grantRepository.findAll().stream().map(Grant::getType).map(
        GrantType::toString).toList();

    this.transactionPropagator
        .withinCurrent(() -> this.clientValidator
                                 .validate(ClientProperties.from(createAction, availableGrants)));

    final var clientId = this.idGenerator.next();
    final var client = createAction.toClient()
                           .withClientId(clientId)
                           .withNewEntity(true);

    final var savedClient = this.clientRepository.save(client);
    return ClientDto.from(savedClient);
  }

  /**
   * Generates a clientSecret and returns to the user for one time look up to save it.
   * Afterwards, there is no way to access the client secret because its value is hashed and stored in the database.
   * @param clientId
   * @return
   */
  @Transactional
  public SecretGenerationResponse generateSecret(String clientId) {
    final var existingClient = this.clientRepository.findById(clientId)
                                   .orElseThrow(() -> new DataNotFoundException("client", clientId, null));

    final var secret = this.secretGenerator.next();
    final var hashedSecret = this.passwordEncoder.encode(secret);

    final var updatedClient = existingClient.withClientSecret(hashedSecret);
    this.clientRepository.save(updatedClient);

    return new SecretGenerationResponse(clientId, secret);
  }
}
