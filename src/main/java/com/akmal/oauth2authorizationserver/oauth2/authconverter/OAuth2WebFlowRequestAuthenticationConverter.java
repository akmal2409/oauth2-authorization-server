package com.akmal.oauth2authorizationserver.oauth2.authconverter;

import com.akmal.oauth2authorizationserver.exception.oauth2.OAuth2AuthorizationException;
import com.akmal.oauth2authorizationserver.oauth2.OAuth2Error;
import com.akmal.oauth2authorizationserver.oauth2.authentication.OAuth2WebFlowAuthenticationDetails;
import com.akmal.oauth2authorizationserver.oauth2.authentication.OAuth2WebFlowRequestAuthentication;
import com.akmal.oauth2authorizationserver.oauth2.config.OAuth2ErrorTypes;
import com.akmal.oauth2authorizationserver.oauth2.config.OAuth2ParameterNames;
import com.akmal.oauth2authorizationserver.oauth2.config.OidcScopes;
import com.akmal.oauth2authorizationserver.oauth2.model.OAuth2CodeChallengeMethod;
import com.akmal.oauth2authorizationserver.oauth2.model.OAuth2ResponseMode;
import com.akmal.oauth2authorizationserver.oauth2.model.OAuth2ResponseType;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import javax.servlet.http.HttpServletRequest;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

public class OAuth2WebFlowRequestAuthenticationConverter implements AuthenticationConverter  {
  public static final String ERROR_URI_HTTP_REQUEST_SPECS = "https://datatracker.ietf.org/doc/html/rfc6749#section-4.2.1";
  private final AuthenticationDetailsSource<HttpServletRequest, OAuth2WebFlowAuthenticationDetails> detailsSource;

  public OAuth2WebFlowRequestAuthenticationConverter(
      AuthenticationDetailsSource<HttpServletRequest, OAuth2WebFlowAuthenticationDetails> detailsSource) {
    this.detailsSource = detailsSource;
  }

  @Override
  public Authentication convert(HttpServletRequest request) {
    if (!HttpMethod.GET.name().equals(request.getMethod())) throwError(OAuth2ErrorTypes.INVALID_REQUEST,
        "Only HTTP GET method is allowed", ERROR_URI_HTTP_REQUEST_SPECS,
        request.getParameter(OAuth2ParameterNames.STATE));

    // as defined in the OAuth2 specification, this parameter is required
    final var clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
    if (!StringUtils.hasText(clientId)) {
      throwError(OAuth2ErrorTypes.INVALID_REQUEST, "client_id is missing", ERROR_URI_HTTP_REQUEST_SPECS,
          request.getParameter(OAuth2ParameterNames.STATE));
    }

    // same as above, the parameter is required
    final var redirectUri = request.getParameter(OAuth2ParameterNames.REDIRECT_URI);
    if (!StringUtils.hasText(redirectUri)) {
      throwError(OAuth2ErrorTypes.INVALID_REQUEST, "redirect_uri is missing", ERROR_URI_HTTP_REQUEST_SPECS,
          request.getParameter(OAuth2ParameterNames.STATE));
    }

    // same as above, the parameter is required
    final var responseTypes = StringUtils.hasText(request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE)) ?
        Arrays.asList(request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE).split(" ")) : List.<String>of();
    final var mappedResponseTypes = responseTypes.stream().map(OAuth2ResponseType::from).toList();

    if (mappedResponseTypes.isEmpty() || mappedResponseTypes.stream().anyMatch(Objects::isNull)) {
      throwError(OAuth2ErrorTypes.INVALID_REQUEST, "Unknown or missing response_type", ERROR_URI_HTTP_REQUEST_SPECS,
          request.getParameter(OAuth2ParameterNames.STATE));
    }

    // minimum 1 scope is required for authentication such as openid
    final var scopes = StringUtils.hasText(request.getParameter(OAuth2ParameterNames.SCOPE)) ?
                           Arrays.asList(request.getParameter(OAuth2ParameterNames.SCOPE).split(",")) : List.<String>of();
    if (!scopes.contains(OidcScopes.OPENID)) {
      throwError(OAuth2ErrorTypes.INVALID_REQUEST, "openid scope is required", null,
          request.getParameter(OAuth2ParameterNames.STATE));
    }

    // other optional parameters
    final var state = request.getParameter(OAuth2ParameterNames.STATE);
    final var codeChallenge = request.getParameter(OAuth2ParameterNames.CODE_CHALLENGE);
    var codeChallengeMethod = OAuth2CodeChallengeMethod.from(request.getParameter(OAuth2ParameterNames.CODE_CHALLENGE_METHOD));

    if (StringUtils.hasText(codeChallenge) && codeChallengeMethod == null) {
      codeChallengeMethod = OAuth2CodeChallengeMethod.S256;
    }

    final var nonce = request.getParameter(OAuth2ParameterNames.NONCE);
    final var idp = request.getParameter(OAuth2ParameterNames.IDP);
    final var idpScopes = StringUtils.hasText(request.getParameter(OAuth2ParameterNames.IDP_SCOPE)) ?
                              Arrays.asList(request.getParameter(OAuth2ParameterNames.IDP_SCOPE).split(",")) :
                              List.<String>of();
    final var responseMode = OAuth2ResponseMode.from(request.getParameter(OAuth2ParameterNames.RESPONSE_MODE));

    final var internalAuthentication = SecurityContextHolder.getContext().getAuthentication(); // nullable, for success auth request needs to be set by the preceding filter-chain

    return new OAuth2WebFlowRequestAuthentication(
        List.of(),
        internalAuthentication,
        internalAuthentication != null && internalAuthentication.isAuthenticated(),
        clientId,
        redirectUri,
        mappedResponseTypes,
        state,
        codeChallenge,
        codeChallengeMethod,
        nonce,
        idp,
        responseMode,
        idpScopes,
        scopes,
        this.detailsSource.buildDetails(request)
    );
  }

  /**
   * Helper method that throws OAuth2 compliant error wrapped in a {@link OAuth2AuthorizationException}
   * class that must be intercepted globally and returned in accordance with the
   * {@link OAuth2Error} schema.
   *
   * @param error one of the {@link com.akmal.oauth2authorizationserver.oauth2.config.OAuth2ErrorTypes}
   * @param description human readable description (optional)
   * @param errorUri to the official specs (optional)
   * @param state that was sent by the user (optional)
   */
  private static void throwError(@NotNull String error, @Nullable String description,
      @Nullable String errorUri, @Nullable String state) {
    throw new OAuth2AuthorizationException(
        new OAuth2Error(error, description, errorUri, state)
    );
  }
}
