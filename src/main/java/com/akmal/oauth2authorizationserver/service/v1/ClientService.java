package com.akmal.oauth2authorizationserver.service.v1;

import com.akmal.oauth2authorizationserver.exception.persistence.DataNotFoundException;
import com.akmal.oauth2authorizationserver.exception.validation.InvalidClientConfigurationException;
import com.akmal.oauth2authorizationserver.idgen.Generator;
import com.akmal.oauth2authorizationserver.repository.client.ClientRepository;
import com.akmal.oauth2authorizationserver.rest.v1.dto.client.ClientDto;
import com.akmal.oauth2authorizationserver.rest.v1.dto.client.SecretGenerationResponse;
import com.akmal.oauth2authorizationserver.rest.v1.dto.client.action.ClientCreateAction;
import com.akmal.oauth2authorizationserver.shared.persistence.TransactionPropagator;
import java.util.Collection;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.apache.commons.validator.routines.UrlValidator;
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

  private final TransactionPropagator transactionPropagator;
  private final PasswordEncoder passwordEncoder;
  private final static UrlValidator URL_VALIDATOR = new UrlValidator(new String[]{"http", "https"});
  private final static String URL_WILDCARD = "*";


  @Transactional(readOnly = true)
  public List<ClientDto> findAllClients() {
    return this.clientRepository
               .findAll()
               .stream()
               .map(ClientDto::from)
               .toList();
  }

  @Transactional
  public ClientDto create(ClientCreateAction createAction) {
    if (!this.areUrlsValid(createAction.signInRedirectUris(), createAction.allowWildcardsInRedirectUrls())) {
      throw new InvalidClientConfigurationException(constructInvalidRedirectUrlMessage(createAction.signInRedirectUris(),
          createAction.allowWildcardsInRedirectUrls(), "sign in redirect URLs"));
    }

    if (!this.areUrlsValid(createAction.signOutRedirectUris(), createAction.allowWildcardsInRedirectUrls())) {
      throw new InvalidClientConfigurationException(constructInvalidRedirectUrlMessage(createAction.signInRedirectUris(),
          createAction.allowWildcardsInRedirectUrls(), "sign out redirect URLs"));
    }

    if (!this.areUrlsValid(createAction.trustedOrigins(), createAction.allowWildcardsInRedirectUrls())) {
      throw new InvalidClientConfigurationException(constructInvalidRedirectUrlMessage(createAction.signInRedirectUris(),
          createAction.allowWildcardsInRedirectUrls(), "trusted origins"));
    }

    final var clientId = this.idGenerator.next();
    final var client = createAction.toClient()
                           .withClientId(clientId);

    final var savedClient = this.clientRepository.save(client);
    return ClientDto.from(savedClient);
  }

  private boolean areUrlsValid(Collection<String> urls, boolean wildcardAllowed) {
    for (String url: urls) {
      if (URL_WILDCARD.equals(url) && wildcardAllowed) continue;

      if (!URL_VALIDATOR.isValid(url)) return false;
    }

    return true;
  }

  private String constructInvalidRedirectUrlMessage(Collection<String> urls, boolean wildcardsAllowed, String collectionName) {
    return String.format("Valid URL with protocol either http or https in %s. "
                             + "If wildcards were used, ensure that the user allowed it. URLs=[%s] "
                             + "Allow wildcards in redirect URLs = %s", collectionName, urls, wildcardsAllowed);
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
