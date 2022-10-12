package com.akmal.oauth2authorizationserver.oauth2.authconverter;

import com.akmal.oauth2authorizationserver.model.client.GrantType;
import com.akmal.oauth2authorizationserver.oauth2.authentication.token.AuthorizationCodeTokenRequestAuthentication;
import com.akmal.oauth2authorizationserver.oauth2.authentication.token.ClientCredentialsTokenRequestAuthentication;
import com.akmal.oauth2authorizationserver.oauth2.authentication.token.HybridTokenRequestAuthentication;
import com.akmal.oauth2authorizationserver.oauth2.authentication.token.RefreshTokenRequestAuthentication;
import com.akmal.oauth2authorizationserver.oauth2.config.OAuth2ErrorTypes;
import com.akmal.oauth2authorizationserver.oauth2.config.OAuth2ParameterNames;
import javax.servlet.http.HttpServletRequest;
import org.springframework.http.HttpMethod;
import org.springframework.security.core.Authentication;
import org.thymeleaf.util.StringUtils;

public class OAuth2TokenRequestAuthenticationConverter extends
    AbstractOAuth2AuthenticationConverter {

  @Override
  public Authentication convert(HttpServletRequest request) {
    if (!HttpMethod.POST.matches(request.getMethod())) {
      throwError(OAuth2ErrorTypes.INVALID_REQUEST, "Only POST method allowed",
          ERROR_URI_HTTP_TOKEN_REQUEST_SPECS, null);
    }

    final var grantType = GrantType.from(request.getParameter(OAuth2ParameterNames.GRANT_TYPE));
    if (grantType == null) {
      throwError(OAuth2ErrorTypes.INVALID_REQUEST, "grant_type is required",
          ERROR_URI_HTTP_TOKEN_REQUEST_SPECS, null);
    }

    final var code = request.getParameter(OAuth2ParameterNames.CODE);
    // if the request is following authorization code or hybrid flow, it is required to have code
    if (StringUtils.isEmpty(code) && isAuthCodeOrHybrid(grantType)) {
      throwError(OAuth2ErrorTypes.INVALID_REQUEST, "code is missing",
          ERROR_URI_HTTP_TOKEN_REQUEST_SPECS, null);
    }

    final var redirectUri = request.getParameter(OAuth2ParameterNames.REDIRECT_URI);
    if (StringUtils.isEmpty(redirectUri) && isAuthCodeOrHybrid(grantType)) {
      throwError(OAuth2ErrorTypes.INVALID_REQUEST, "redirect_uri is missing",
          ERROR_URI_HTTP_TOKEN_REQUEST_SPECS, null);
    }

    final var codeVerifier = request.getParameter(OAuth2ParameterNames.CODE_VERIFIER);
    final var refreshToken = request.getParameter(OAuth2ParameterNames.REFRESH_TOKEN);
    if (StringUtils.isEmpty(refreshToken) && GrantType.REFRESH_TOKEN.equals(grantType)) {
      throwError(OAuth2ErrorTypes.INVALID_REQUEST, "refresh_token is missing",
          ERROR_URI_HTTP_TOKEN_REQUEST_SPECS, null);
    }

    final var clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
    if (StringUtils.isEmpty(clientId)) {
      throwError(OAuth2ErrorTypes.INVALID_REQUEST, "client_id is missing",
          ERROR_URI_HTTP_TOKEN_REQUEST_SPECS, null);
    }

    final var clientSecret = request.getParameter(OAuth2ParameterNames.CLIENT_SECRET);
    if (StringUtils.isEmpty(clientSecret) && GrantType.CLIENT_CREDENTIALS.equals(grantType)) {
      throwError(OAuth2ErrorTypes.INVALID_REQUEST, "client_credentials is missing",
          ERROR_URI_HTTP_TOKEN_REQUEST_SPECS, null);
    }

    // only for refresh_token grant, must be subset of the requested scopes
    final var scopes = extractMultiValueParam(request, OAuth2ParameterNames.SCOPE, ",");

    return switch (grantType) {
      case AUTHORIZATION_CODE_PKCE ->
          new AuthorizationCodeTokenRequestAuthentication(clientId, code, codeVerifier,
              redirectUri);
      case HYBRID -> new HybridTokenRequestAuthentication(clientId, code);
      case REFRESH_TOKEN -> new RefreshTokenRequestAuthentication(clientId, refreshToken, scopes);
      case CLIENT_CREDENTIALS ->
          new ClientCredentialsTokenRequestAuthentication(clientId, clientSecret);
      default -> null;
    };
  }

  private static boolean isAuthCodeOrHybrid(GrantType grantType) {
    return GrantType.AUTHORIZATION_CODE_PKCE.equals(grantType) ||
               GrantType.HYBRID.equals(grantType);
  }
}
