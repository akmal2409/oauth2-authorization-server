package com.akmal.oauth2authorizationserver.parser.auth;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import com.akmal.oauth2authorizationserver.config.authentication.AuthenticationAttributes;
import com.akmal.oauth2authorizationserver.model.authentication.AuthResponseType;
import com.akmal.oauth2authorizationserver.model.authentication.AuthenticationProperties;
import com.akmal.oauth2authorizationserver.model.authentication.CodeChallengeMethod;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class AuthenticationAttributeToPropertiesParserTest {

  AuthenticationAttributeToPropertiesParser parser = new AuthenticationAttributeToPropertiesParser();


  @Test
  @DisplayName("Test should pass by parsing all attributes from a Map")
  void testShouldParseAllAttributes() {
    final var properties = Map.of(
        AuthenticationAttributes.CLIENT_ID, "clientId",
        AuthenticationAttributes.REDIRECT_URI, "http://localhost:8080",
        AuthenticationAttributes.RESPONSE_TYPE, AuthResponseType.CODE.toString().toLowerCase(),
        AuthenticationAttributes.STATE, "state",
        AuthenticationAttributes.CODE_CHALLENGE, "challenge",
        AuthenticationAttributes.CODE_CHALLENGE_METHOD, CodeChallengeMethod.S256.toString().toLowerCase(),
        AuthenticationAttributes.NONCE, "nonce",
        AuthenticationAttributes.IDP, "idp",
        AuthenticationAttributes.IDP_SCOPE, "idpscope,another_scope",
        AuthenticationAttributes.SCOPE, "hey_scope"
    );

    final var expectedProperties = new AuthenticationProperties(
        properties.get(AuthenticationAttributes.CLIENT_ID),
        properties.get(AuthenticationAttributes.REDIRECT_URI),
        AuthResponseType.CODE,
        properties.get(AuthenticationAttributes.STATE),
        properties.get(AuthenticationAttributes.CODE_CHALLENGE),
        CodeChallengeMethod.S256,
        properties.get(AuthenticationAttributes.NONCE),
        properties.get(AuthenticationAttributes.IDP),
        List.of("idpscope", "another_scope"),
        List.of("hey_scope")
    );

    final var actualProperties = parser.parse(properties);

    assertThat(actualProperties)
        .usingRecursiveComparison()
        .usingDefaultComparator()
        .isEqualTo(expectedProperties);
  }

  @Test
  @DisplayName("Test should verify that empty scope parameter returns an empty list")
  void testShouldReturnEmptyListWhenScopesAreEmpty() {
    final var properties = Map.of(
        AuthenticationAttributes.SCOPE, ""
    );

    final var actualProps = this.parser.parse(properties);

    assertThat(actualProps).extracting(AuthenticationProperties::scopes)
        .isNotNull()
        .asList()
        .isEmpty();
  }

  @Test
  @DisplayName("Test should verify that empty idp_scope parameter returns an empty list")
  void testShouldReturnEmptyListWhenIdpScopesAreEmpty() {
    final var properties = Map.of(
        AuthenticationAttributes.IDP_SCOPE, ""
    );

    final var actualProps = this.parser.parse(properties);

    assertThat(actualProps).extracting(AuthenticationProperties::idpScopes)
        .isNotNull()
        .asList()
        .isEmpty();
  }
}
