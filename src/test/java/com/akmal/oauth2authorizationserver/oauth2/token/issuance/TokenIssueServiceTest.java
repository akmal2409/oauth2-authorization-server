package com.akmal.oauth2authorizationserver.oauth2.token.issuance;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

import com.akmal.oauth2authorizationserver.config.InternalOAuth2ConfigurationProperties;
import com.akmal.oauth2authorizationserver.crypto.RsaKeyService;
import com.akmal.oauth2authorizationserver.model.client.GrantType;
import com.akmal.oauth2authorizationserver.model.user.User;
import com.akmal.oauth2authorizationserver.oauth2.config.OidcScopes;
import com.akmal.oauth2authorizationserver.repository.UserRepository;
import com.akmal.oauth2authorizationserver.shared.persistence.TransactionPropagator;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class TokenIssueServiceTest {
  @Mock
  RsaKeyService rsaKeyService;
  @Spy
  ObjectMapper objectMapper = new ObjectMapper();

  @Mock
  InternalOAuth2ConfigurationProperties internalOauthConfigProps;
  @Spy
  TransactionPropagator transactionPropagator = new TransactionPropagator();
  @Mock
  UserRepository userRepository;

  @InjectMocks
  TokenIssueService tokenIssueService;

  static KeyPair keyPair;


  @BeforeAll
  static void init() {
    try {
      final var generator = KeyPairGenerator.getInstance("RSA");
      generator.initialize(2048);
      keyPair = generator.generateKeyPair();
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  @Test
  @DisplayName("Should return an id token if the openid scope is present")
  void testIssuesIdTokenWhenOpenIdScopeIsPresent() {
    OAuth2TokenIssueProperties props = new OAuth2TokenIssueProperties("test", "test_client",
        List.of(OidcScopes.OPENID), GrantType.AUTHORIZATION_CODE_PKCE);

    when(rsaKeyService.getKeyPair()).thenReturn(keyPair);
    when(internalOauthConfigProps.getIssuerUrl()).thenReturn("http://localhost:8080");
    when(internalOauthConfigProps.getTokenValidityMs()).thenReturn(100L);
    when(userRepository.findById(anyString())).thenReturn(Optional.of(new User()));

    final var tokenSet = tokenIssueService.issueTokenSet(props);

    assertThat((String) tokenSet.get(OAuth2TokenAttributeNames.ID_TOKEN))
        .isNotNull();
    assertThat(tokenSet.get(OAuth2TokenAttributeNames.ACCESS_TOKEN))
        .isNotNull();
    assertThat(tokenSet.get(OAuth2TokenAttributeNames.REFRESH_TOKEN))
        .isNull();
  }

  @Test
  @DisplayName("Should return access token with minimal properties set")
  void testIssueAccessTokenWithMinimalProps() {
    OAuth2TokenIssueProperties props = new OAuth2TokenIssueProperties("test", "test_client",
        List.of(), GrantType.AUTHORIZATION_CODE_PKCE);
    when(rsaKeyService.getKeyPair()).thenReturn(keyPair);
    when(internalOauthConfigProps.getIssuerUrl()).thenReturn("http://localhost:8080");
    when(internalOauthConfigProps.getTokenValidityMs()).thenReturn(100L);

    final var tokenSet = tokenIssueService.issueTokenSet(props);

    assertThat((String) tokenSet.get(OAuth2TokenAttributeNames.ACCESS_TOKEN))
        .isNotNull();
    assertThat(tokenSet.get(OAuth2TokenAttributeNames.ID_TOKEN))
        .isNull();
    assertThat(tokenSet.get(OAuth2TokenAttributeNames.REFRESH_TOKEN))
        .isNull();
  }

  @Test
  @DisplayName("Should issue refresh token when offline_access scope is present")
  void testIssueRefreshTokenWhenOfflineAccessScopePresent() {
    OAuth2TokenIssueProperties props = new OAuth2TokenIssueProperties("test", "test_client",
        List.of(OidcScopes.OFFLINE_ACCESS), GrantType.AUTHORIZATION_CODE_PKCE);
    when(rsaKeyService.getKeyPair()).thenReturn(keyPair);
    when(internalOauthConfigProps.getIssuerUrl()).thenReturn("http://localhost:8080");
    when(internalOauthConfigProps.getTokenValidityMs()).thenReturn(100L);

    final var tokenSet = tokenIssueService.issueTokenSet(props);

    assertThat((String) tokenSet.get(OAuth2TokenAttributeNames.REFRESH_TOKEN))
        .isNotNull();
    assertThat((String) tokenSet.get(OAuth2TokenAttributeNames.ACCESS_TOKEN))
        .isNotNull();
    assertThat((String) tokenSet.get(OAuth2TokenAttributeNames.ID_TOKEN))
        .isNull();

  }
}
