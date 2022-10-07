package com.akmal.oauth2authorizationserver.oauth2.authconverter;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.akmal.oauth2authorizationserver.exception.oauth2.OAuth2AuthorizationException;
import com.akmal.oauth2authorizationserver.oauth2.OAuth2Error;
import com.akmal.oauth2authorizationserver.oauth2.authentication.OAuth2WebFlowAuthenticationDetails;
import com.akmal.oauth2authorizationserver.oauth2.authentication.OAuth2WebFlowRequestAuthentication;
import com.akmal.oauth2authorizationserver.oauth2.config.OAuth2ErrorTypes;
import com.akmal.oauth2authorizationserver.oauth2.config.OAuth2ParameterNames;
import com.akmal.oauth2authorizationserver.oauth2.model.OAuth2CodeChallengeMethod;
import com.akmal.oauth2authorizationserver.oauth2.model.OAuth2ResponseMode;
import com.akmal.oauth2authorizationserver.oauth2.model.OAuth2ResponseType;
import java.util.List;
import java.util.stream.Collectors;
import javax.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationDetailsSource;

@ExtendWith(MockitoExtension.class)
class OAuth2WebFlowRequestAuthenticationConverterTest {

  @Mock
  AuthenticationDetailsSource<HttpServletRequest, OAuth2WebFlowAuthenticationDetails> detailsSource;

  @InjectMocks
  OAuth2WebFlowRequestAuthenticationConverter authConverter;

  @Mock
  HttpServletRequest mockRequest;

  @Test
  @DisplayName("Test conversion should throw an invalid request error when request is not HTTP GET")
  void testShouldThrowErrorWhenMethodNotGet() {
    final var expectedState = "state";

    final var expectedError = new OAuth2Error(OAuth2ErrorTypes.INVALID_REQUEST,
        "Only HTTP GET method is allowed", OAuth2WebFlowRequestAuthenticationConverter.ERROR_URI_HTTP_REQUEST_SPECS,
        expectedState);

    when(mockRequest.getMethod()).thenReturn(HttpMethod.POST.name());
    when(mockRequest.getParameter(anyString())).thenReturn(expectedState);

    assertThatThrownBy(() -> {
      authConverter.convert(mockRequest);
    }, "Expected OAuth2Error of type invalid_request")
        .isInstanceOf(OAuth2AuthorizationException.class)
        .extracting("error")
        .usingRecursiveComparison()
        .isEqualTo(expectedError);
  }

  @Test
  @DisplayName("Test conversion should throw an invalid request error when client_id is missing")
  void testShouldThrowErrorWhenClientIdMissing() {
    final var expectedState = "state";

    final var expectedError = new OAuth2Error(OAuth2ErrorTypes.INVALID_REQUEST,
        "client_id is missing", OAuth2WebFlowRequestAuthenticationConverter.ERROR_URI_HTTP_REQUEST_SPECS,
        expectedState);

    when(mockRequest.getMethod()).thenReturn(HttpMethod.GET.name());
    when(mockRequest.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(null);
    when(mockRequest.getParameter(OAuth2ParameterNames.STATE)).thenReturn(expectedState);


    assertThatThrownBy(() -> {
      authConverter.convert(mockRequest);
    }, "Expected OAuth2Error of type invalid_request")
        .isInstanceOf(OAuth2AuthorizationException.class)
        .extracting("error")
        .usingRecursiveComparison()
        .isEqualTo(expectedError);
  }

  @Test
  @DisplayName("Test conversion should throw an invalid request error when redirect_uri is missing")
  void testShouldThrowErrorWhenRedirectUriMissing() {
    final var expectedState = "state";

    final var expectedError = new OAuth2Error(OAuth2ErrorTypes.INVALID_REQUEST,
        "redirect_uri is missing", OAuth2WebFlowRequestAuthenticationConverter.ERROR_URI_HTTP_REQUEST_SPECS,
        expectedState);

    when(mockRequest.getMethod()).thenReturn(HttpMethod.GET.name());
    when(mockRequest.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn("some_value");
    when(mockRequest.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(null);
    when(mockRequest.getParameter(OAuth2ParameterNames.STATE)).thenReturn(expectedState);


    assertThatThrownBy(() -> {
      authConverter.convert(mockRequest);
    }, "Expected OAuth2Error of type invalid_request")
        .isInstanceOf(OAuth2AuthorizationException.class)
        .extracting("error")
        .usingRecursiveComparison()
        .isEqualTo(expectedError);
  }

  @Test
  @DisplayName("Test conversion should throw an invalid request error when response_type is missing")
  void testShouldThrowErrorWhenResponseTypeMissing() {
    final var expectedState = "state";

    final var expectedError = new OAuth2Error(OAuth2ErrorTypes.INVALID_REQUEST,
        "Unknown or missing response_type", OAuth2WebFlowRequestAuthenticationConverter.ERROR_URI_HTTP_REQUEST_SPECS,
        expectedState);

    when(mockRequest.getMethod()).thenReturn(HttpMethod.GET.name());
    when(mockRequest.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn("some_value");
    when(mockRequest.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn("value");
    when(mockRequest.getParameter(OAuth2ParameterNames.RESPONSE_TYPE)).thenReturn(null);
    when(mockRequest.getParameter(OAuth2ParameterNames.STATE)).thenReturn(expectedState);


    assertThatThrownBy(() -> {
      authConverter.convert(mockRequest);
    }, "Expected OAuth2Error of type invalid_request")
        .isInstanceOf(OAuth2AuthorizationException.class)
        .extracting("error")
        .usingRecursiveComparison()
        .isEqualTo(expectedError);
  }

  @Test
  @DisplayName("Test conversion should throw an invalid request error when invalid response_type passed")
  void testShouldThrowErrorWhenInvalidResponseTypePasses() {
    final var expectedState = "state";

    final var expectedError = new OAuth2Error(OAuth2ErrorTypes.INVALID_REQUEST,
        "Unknown or missing response_type", OAuth2WebFlowRequestAuthenticationConverter.ERROR_URI_HTTP_REQUEST_SPECS,
        expectedState);

    when(mockRequest.getMethod()).thenReturn(HttpMethod.GET.name());
    when(mockRequest.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn("some_value");
    when(mockRequest.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn("value");
    when(mockRequest.getParameter(OAuth2ParameterNames.RESPONSE_TYPE)).thenReturn("invalid");
    when(mockRequest.getParameter(OAuth2ParameterNames.STATE)).thenReturn(expectedState);


    assertThatThrownBy(() -> {
      authConverter.convert(mockRequest);
    }, "Expected OAuth2Error of type invalid_request")
        .isInstanceOf(OAuth2AuthorizationException.class)
        .extracting("error")
        .usingRecursiveComparison()
        .isEqualTo(expectedError);
  }

  @Test
  @DisplayName("Test conversion should throw an invalid request error when scope is missing")
  void testShouldThrowErrorWhenOpenIdScopeMissing() {
    final var expectedState = "state";

    final var expectedError = new OAuth2Error(OAuth2ErrorTypes.INVALID_REQUEST,
        "openid scope is required", null,
        expectedState);

    when(mockRequest.getMethod()).thenReturn(HttpMethod.GET.name());
    when(mockRequest.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn("some_value");
    when(mockRequest.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn("value");
    when(mockRequest.getParameter(OAuth2ParameterNames.RESPONSE_TYPE)).thenReturn(
        OAuth2ResponseType.CODE.name());
    when(mockRequest.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn("another_scope");
    when(mockRequest.getParameter(OAuth2ParameterNames.STATE)).thenReturn(expectedState);


    assertThatThrownBy(() -> {
      authConverter.convert(mockRequest);
    }, "Expected OAuth2Error of type invalid_request")
        .isInstanceOf(OAuth2AuthorizationException.class)
        .extracting("error")
        .usingRecursiveComparison()
        .isEqualTo(expectedError);
  }

  @Test
  @DisplayName("Test conversion should throw an invalid request error when no scope provided")
  void testShouldThrowErrorWhenOpenIdScopeMissingNoScopes() {
    final var expectedState = "state";

    final var expectedError = new OAuth2Error(OAuth2ErrorTypes.INVALID_REQUEST,
        "openid scope is required", null,
        expectedState);

    when(mockRequest.getMethod()).thenReturn(HttpMethod.GET.name());
    when(mockRequest.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn("some_value");
    when(mockRequest.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn("value");
    when(mockRequest.getParameter(OAuth2ParameterNames.RESPONSE_TYPE)).thenReturn(
        OAuth2ResponseType.CODE.name());
    when(mockRequest.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn(null);
    when(mockRequest.getParameter(OAuth2ParameterNames.STATE)).thenReturn(expectedState);


    assertThatThrownBy(() -> {
      authConverter.convert(mockRequest);
    }, "Expected OAuth2Error of type invalid_request")
        .isInstanceOf(OAuth2AuthorizationException.class)
        .extracting("error")
        .usingRecursiveComparison()
        .isEqualTo(expectedError);
  }

  @Test
  @DisplayName("Test conversion should convert all properties")
  void testShouldConvertAllProperties() {
    final var expectedAuthentication = new OAuth2WebFlowRequestAuthentication(
        List.of(),
        null,
        false,
        "client_id",
        "https://google.com",
        List.of(OAuth2ResponseType.CODE),
        "state",
        "challenge",
        OAuth2CodeChallengeMethod.S256,
        "nonce",
        "idp",
        OAuth2ResponseMode.QUERY,
        List.of("openid"),
        List.of("openid"),
        null
    );

    when(mockRequest.getMethod()).thenReturn(HttpMethod.GET.name());
    when(mockRequest.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(expectedAuthentication.getClientId());
    when(mockRequest.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(expectedAuthentication.getRedirectUri());
    when(mockRequest.getParameter(OAuth2ParameterNames.RESPONSE_TYPE)).thenReturn(
        expectedAuthentication.getResponseTypes().stream().map(OAuth2ResponseType::name).collect(
            Collectors.joining(" ")));
    when(mockRequest.getParameter(OAuth2ParameterNames.CODE_CHALLENGE)).thenReturn(expectedAuthentication.getCodeChallenge());
    when(mockRequest.getParameter(OAuth2ParameterNames.CODE_CHALLENGE_METHOD)).thenReturn(OAuth2CodeChallengeMethod.S256.name());
    when(mockRequest.getParameter(OAuth2ParameterNames.IDP)).thenReturn(expectedAuthentication.getIdp());
    when(mockRequest.getParameter(OAuth2ParameterNames.IDP_SCOPE)).thenReturn(String.join(",", expectedAuthentication.getIdpScopes()));
    when(mockRequest.getParameter(OAuth2ParameterNames.NONCE)).thenReturn(expectedAuthentication.getNonce());
    when(mockRequest.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn(String.join(",", expectedAuthentication.getScopes()));
    when(mockRequest.getParameter(OAuth2ParameterNames.RESPONSE_MODE)).thenReturn(expectedAuthentication.getResponseMode().name());
    when(mockRequest.getParameter(OAuth2ParameterNames.STATE)).thenReturn(expectedAuthentication.getState());
    when(detailsSource.buildDetails(any())).thenReturn(null);


    final var actualAuthentication = authConverter.convert(mockRequest);

    assertThat(actualAuthentication)
        .usingRecursiveComparison()
        .isEqualTo(expectedAuthentication);
  }
}
