package com.akmal.oauth2authorizationserver.service.v1;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.akmal.oauth2authorizationserver.exception.validation.InvalidClientConfigurationException;
import com.akmal.oauth2authorizationserver.idgen.Generator;
import com.akmal.oauth2authorizationserver.idgen.ShortenedUUIDGenerator;
import com.akmal.oauth2authorizationserver.model.client.Client;
import com.akmal.oauth2authorizationserver.model.client.Grant;
import com.akmal.oauth2authorizationserver.model.client.GrantType;
import com.akmal.oauth2authorizationserver.model.client.Scope;
import com.akmal.oauth2authorizationserver.repository.ScopeRepository;
import com.akmal.oauth2authorizationserver.repository.client.ClientRepository;
import com.akmal.oauth2authorizationserver.repository.client.GrantRepository;
import com.akmal.oauth2authorizationserver.rest.v1.dto.client.action.ClientCreateAction;
import com.akmal.oauth2authorizationserver.service.v1.client.ClientService;
import com.akmal.oauth2authorizationserver.shared.persistence.TransactionPropagator;
import com.akmal.oauth2authorizationserver.validator.client.ClientProperties;
import com.akmal.oauth2authorizationserver.validator.client.ClientValidator;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class ClientServiceTest {

  @Mock
  ClientRepository clientRepository;

  @Mock
  ClientValidator clientValidator;

  @Mock
  GrantRepository grantRepository;

  @Mock
  ScopeRepository scopeRepository;

  @Captor
  ArgumentCaptor<Client> clientArgumentCaptor;

  @Spy
  Generator<String> idGenerator = new ShortenedUUIDGenerator();

  @Spy
  TransactionPropagator transactionPropagator = new TransactionPropagator();

  @InjectMocks
  ClientService clientService;


  @Test
  @DisplayName("Test should successfully assert that createClient() generates id for a new client")
  void testCreateGeneratesId() {
    final ClientCreateAction createAction = new ClientCreateAction(
        null, List.of(), List.of("http://localhost.com"), List.of("http://localhost.com"), List.of("http://localhost.com"), false,
        false
    );

    when(this.clientRepository.save(any(Client.class))).thenReturn(new Client());
    when(this.clientValidator.validate(any())).thenReturn(true);
    this.clientService.create(createAction);
    verify(this.clientRepository).save(this.clientArgumentCaptor.capture());
    verify(this.clientValidator, times(1)).validate(any(ClientProperties.class));

    Client clientBeforeSave = clientArgumentCaptor.getValue();

    assertThat(clientBeforeSave).extracting("clientId")
        .asString()
        .isNotNull();
  }

  @Test
  @DisplayName("Tests whether default OIDC scopes are added to the client upon creation")
  void testAddOidcScopes() {
    final ClientCreateAction createAction = new ClientCreateAction(
        null, List.of(), List.of("http://localhost.com"), List.of("http://localhost.com"), List.of("http://localhost.com"), false,
        false
    );
    final List<Scope> expectedScopes =
        List.of(new Scope(1, "profile", true, "description"));

    when(this.scopeRepository.findAllOidcScopes()).thenReturn(expectedScopes);
    when(this.clientRepository.save(any(Client.class))).thenReturn(new Client());

    this.clientService.create(createAction);
    verify(this.clientRepository).save(this.clientArgumentCaptor.capture());


    final var capturedClient = this.clientArgumentCaptor
                                       .getValue();

    assertThat(capturedClient.getAllowedScopes())
            .asList()
                .hasSize(1)
                    .isEqualTo(expectedScopes);



    verify(this.scopeRepository, times(1)).findAllOidcScopes();
  }

  @Test
  @DisplayName("Test should successfully assert that the repository call save() must receive all the passes values")
  void testCreatePassesAllFields() {
    final ClientCreateAction createAction = new ClientCreateAction(
        "Test Name", List.of("AUTHORIZATION_CODE_PKCE"), List.of("http://localhost.com"),
        List.of("http://localhost.com"), List.of("http://localhost.com"), false,
        false
    );

    when(this.clientRepository.save(any(Client.class))).thenReturn(new Client());
    this.clientService.create(createAction);
    verify(this.clientRepository).save(this.clientArgumentCaptor.capture());

    Client clientBeforeSave = clientArgumentCaptor.getValue();

    assertThat(clientBeforeSave)
        .isNotNull();

    assertThat(clientBeforeSave.getName()).isEqualTo(createAction.name());
    assertThat(clientBeforeSave.getGrants().stream().map(Grant::getType).map(GrantType::toString).toList()).isEqualTo(createAction.grants());
    assertThat(clientBeforeSave.getTrustedOrigins()).isEqualTo(createAction.trustedOrigins());
    assertThat(clientBeforeSave.getSignInRedirectUris()).isEqualTo(createAction.signInRedirectUris());
    assertThat(clientBeforeSave.getSignOutRedirectUris()).isEqualTo(createAction.signOutRedirectUris());
  }
}


