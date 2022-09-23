package com.akmal.oauth2authorizationserver.service.v1;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.akmal.oauth2authorizationserver.exception.validation.InvalidClientConfigurationException;
import com.akmal.oauth2authorizationserver.idgen.Generator;
import com.akmal.oauth2authorizationserver.idgen.ShortenedUUIDGenerator;
import com.akmal.oauth2authorizationserver.model.client.Client;
import com.akmal.oauth2authorizationserver.model.client.Grant;
import com.akmal.oauth2authorizationserver.model.client.GrantType;
import com.akmal.oauth2authorizationserver.repository.client.ClientRepository;
import com.akmal.oauth2authorizationserver.rest.v1.dto.client.action.ClientCreateAction;
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

  @Captor
  ArgumentCaptor<Client> clientArgumentCaptor;

  @Spy
  Generator<String> idGenerator = new ShortenedUUIDGenerator();

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
    this.clientService.create(createAction);
    verify(this.clientRepository).save(this.clientArgumentCaptor.capture());

    Client clientBeforeSave = clientArgumentCaptor.getValue();

    assertThat(clientBeforeSave).extracting("clientId")
        .asString()
        .isNotNull();
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

  @Test
  @DisplayName("Test should fail when invalid URL is passes to the sign in redirect")
  void testShouldFailWhenInvalidSignInRedirectUrlsPassed() {
    final ClientCreateAction createAction = new ClientCreateAction(
        null, List.of(), List.of("http://localhost.com", "http:/aloha.net/", "ftp://dropbox.com"),
        List.of(), List.of(), false,
        false
    );

    assertThatThrownBy(() -> {
      this.clientService.create(createAction);
    }, "Expected client service to throw InvalidClientConfigurationException due to invalid URLs").isInstanceOf(InvalidClientConfigurationException.class);
  }

  @Test
  @DisplayName("Test should fail when invalid URL is passes to the sign out redirect")
  void testShouldFailWhenInvalidSignOutRedirectUrlsPassed() {
    final ClientCreateAction createAction = new ClientCreateAction(
        null, List.of(), List.of(),
        List.of("http://localhost.com", "http:/aloha.net/", "ftp://dropbox.com"), List.of(), false,
        false
    );

    assertThatThrownBy(() -> {
      this.clientService.create(createAction);
    }, "Expected client service to throw InvalidClientConfigurationException due to invalid URLs").isInstanceOf(InvalidClientConfigurationException.class);
  }

  @Test
  @DisplayName("Test should fail when invalid URL is passes to the trusted origins")
  void testShouldFailWhenInvalidTrustedOriginUrlsPassed() {
    final ClientCreateAction createAction = new ClientCreateAction(
        null, List.of(), List.of(),
        List.of(), List.of("http://localhost.com", "http:/aloha.net/", "ftp://dropbox.com"), false,
        false
    );

    assertThatThrownBy(() -> {
      this.clientService.create(createAction);
    }, "Expected client service to throw InvalidClientConfigurationException due to invalid URLs").isInstanceOf(InvalidClientConfigurationException.class);
  }
}


