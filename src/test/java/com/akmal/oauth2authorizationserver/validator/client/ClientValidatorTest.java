package com.akmal.oauth2authorizationserver.validator.client;

import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;

import com.akmal.oauth2authorizationserver.exception.validation.InvalidClientConfigurationException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class ClientValidatorTest {
  static final Collection<String> ALLOWED_GRANTS = List.of("AUTHORIZATION_CODE_PKCE");

  ClientValidator clientValidator = new ClientValidator();

  @Test
  @DisplayName("Test should fail when invalid URL is passes to the sign in redirect")
  void testShouldFailWhenInvalidSignInRedirectUrlsPassed() {
    final ClientProperties clientProperties = new ClientProperties(
        "Name", List.of(), ALLOWED_GRANTS, List.of("http://localhost.com", "http:/aloha.net/", "ftp://dropbox.com"),
        List.of(),
        List.of(), false
    );

    assertThatThrownBy(() -> {
      clientValidator.validate(clientProperties);
    }, "Expected client service to throw InvalidClientConfigurationException due to invalid URLs").isInstanceOf(
        InvalidClientConfigurationException.class);
  }

  @Test
  @DisplayName("Test should fail when invalid URL is passes to the sign out redirect")
  void testShouldFailWhenInvalidSignOutRedirectUrlsPassed() {
    final ClientProperties clientProperties = new ClientProperties(
        "Name", List.of(), ALLOWED_GRANTS,
        List.of(),
        List.of("http://localhost.com", "http:/aloha.net/", "ftp://dropbox.com"),
        List.of(), false
    );

    assertThatThrownBy(() -> {
      this.clientValidator.validate(clientProperties);
    }, "Expected client service to throw InvalidClientConfigurationException due to invalid URLs").isInstanceOf(InvalidClientConfigurationException.class);
  }

  @Test
  @DisplayName("Test should fail when invalid URL is passes to the trusted origins")
  void testShouldFailWhenInvalidTrustedOriginUrlsPassed() {
    final ClientProperties clientProperties = new ClientProperties(
        "Name", List.of(), ALLOWED_GRANTS,
        List.of(),
        List.of(),
        List.of("http://localhost.com", "http:/aloha.net/", "ftp://dropbox.com"), false
    );

    assertThatThrownBy(() -> {
      this.clientValidator.validate(clientProperties);
    }, "Expected client service to throw InvalidClientConfigurationException due to invalid URLs").isInstanceOf(InvalidClientConfigurationException.class);
  }

  @Test
  @DisplayName("Test should fail when wildcard was passed to sign in url without permission")
  void testShouldFailWhenWildcardPresentSignIn() {
    final ClientProperties clientProperties = new ClientProperties(
        "Name", List.of(), ALLOWED_GRANTS,
        List.of("*"),
        List.of(),
        List.of(), false
    );
    assertThatThrownBy(() -> {
      this.clientValidator.validate(clientProperties);
    }, "Expected client service to throw InvalidClientConfigurationException due to invalid URLs").isInstanceOf(InvalidClientConfigurationException.class);
  }

  @Test
  @DisplayName("Test should fail when wildcard was passed to sign out url without permission")
  void testShouldFailWhenWildcardPresentSignOut() {
    final ClientProperties clientProperties = new ClientProperties(
        "Name", List.of(), ALLOWED_GRANTS,
        List.of(),
        List.of("*"),
        List.of(), false
    );
    assertThatThrownBy(() -> {
      this.clientValidator.validate(clientProperties);
    }, "Expected client service to throw InvalidClientConfigurationException due to invalid URLs").isInstanceOf(InvalidClientConfigurationException.class);
  }

  @Test
  @DisplayName("Test should fail when wildcard was passed to trusted origin url without permission")
  void testShouldFailWhenWildcardPresentTrustedOrigin() {
    final ClientProperties clientProperties = new ClientProperties(
        "Name", List.of(), ALLOWED_GRANTS,
        List.of(),
        List.of(),
        List.of("*"), false
    );
    assertThatThrownBy(() -> {
      this.clientValidator.validate(clientProperties);
    }, "Expected client service to throw InvalidClientConfigurationException due to invalid URLs").isInstanceOf(InvalidClientConfigurationException.class);
  }

  @Test
  @DisplayName("Test should fail when duplicate grant is passed")
  void testShouldFailDuplicateGrant() {
    final Collection<String> grants = new ArrayList<>(ALLOWED_GRANTS);
    grants.add(ALLOWED_GRANTS.iterator().next());

    final ClientProperties clientProperties = new ClientProperties(
        "Name", grants, ALLOWED_GRANTS,
        List.of(),
        List.of(),
        List.of(), false
    );
    assertThatThrownBy(() -> {
      this.clientValidator.validate(clientProperties);
    }, "Expected client service to throw InvalidClientConfigurationException due to duplicate grant").isInstanceOf(InvalidClientConfigurationException.class);
  }

  @Test
  @DisplayName("Test should fail when unknown grant is passed")
  void testShouldFailUnknownGrant() {
    final Collection<String> grants = new ArrayList<>(ALLOWED_GRANTS);
    grants.add("NON_EXISTENT");

    final ClientProperties clientProperties = new ClientProperties(
        "Name", grants, ALLOWED_GRANTS,
        List.of(),
        List.of(),
        List.of(), false
    );
    assertThatThrownBy(() -> {
      this.clientValidator.validate(clientProperties);
    }, "Expected client service to throw InvalidClientConfigurationException due to unknown grant").isInstanceOf(InvalidClientConfigurationException.class);
  }
}
