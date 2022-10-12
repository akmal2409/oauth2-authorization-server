package com.akmal.oauth2authorizationserver.oauth2.authconverter;

import com.akmal.oauth2authorizationserver.exception.oauth2.OAuth2AuthorizationException;
import com.akmal.oauth2authorizationserver.oauth2.OAuth2Error;
import java.util.Arrays;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

public abstract class AbstractOAuth2AuthenticationConverter implements AuthenticationConverter {
  public static final String ERROR_URI_HTTP_REQUEST_SPECS = "https://datatracker.ietf.org/doc/html/rfc6749#section-4.2.1";
  public static final String ERROR_URI_HTTP_TOKEN_REQUEST_SPECS = "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3";

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
  protected static void throwError(@NotNull String error, @Nullable String description,
      @Nullable String errorUri, @Nullable String state) {
    throw new OAuth2AuthorizationException(
        new OAuth2Error(error, description, errorUri, state)
    );
  }

  protected List<String> extractMultiValueParam(HttpServletRequest request, String param, String delimiter) {
    return StringUtils.hasText(request.getParameter(param)) ?
                           Arrays.asList(request.getParameter(param).split(delimiter)) : List.<String>of();
  }
}
