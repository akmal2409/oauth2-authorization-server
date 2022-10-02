package com.akmal.oauth2authorizationserver.web.filter.oauth2;

import com.akmal.oauth2authorizationserver.oauth2.OAuth2WebFlowAuthenticationDetailsSource;
import com.akmal.oauth2authorizationserver.oauth2.authconverter.OAuth2WebFlowRequestAuthenticationConverter;
import com.akmal.oauth2authorizationserver.oauth2.authentication.OAuth2WebFlowAuthenticationDetails;
import com.akmal.oauth2authorizationserver.oauth2.authentication.OAuth2WebFlowConsentAuthentication;
import com.akmal.oauth2authorizationserver.oauth2.config.OAuth2ParameterNames;
import com.akmal.oauth2authorizationserver.oauth2.config.OidcScopes;
import java.io.IOException;
import java.util.List;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

public class OAuth2AuthorizationEndpointFilter extends OncePerRequestFilter {
  private static final String DEFAULT_AUTHORIZATION_ENDPOINT_URL = "/authorize";
  private static final Authentication ANONYMOUS_AUTHENTICATION = new AnonymousAuthenticationToken(
      "anonymous", "anonymousUser", List.of(new SimpleGrantedAuthority("ROLE_ANONYMOUS"))
  );
  private final RequestMatcher requestMatcher;
  private final String endpointUrl;
  private final AuthenticationConverter authenticationConverter;
  private final AuthenticationDetailsSource<HttpServletRequest, OAuth2WebFlowAuthenticationDetails> detailsSource;

  public OAuth2AuthorizationEndpointFilter(String endpointUrl) {
    this.endpointUrl = endpointUrl;
    this.requestMatcher = this.buildRequestMatcher();
    this.detailsSource = new OAuth2WebFlowAuthenticationDetailsSource();
    this.authenticationConverter = new OAuth2WebFlowRequestAuthenticationConverter(this.detailsSource);
  }

  public OAuth2AuthorizationEndpointFilter() {
    this(DEFAULT_AUTHORIZATION_ENDPOINT_URL);
  }

  private RequestMatcher buildRequestMatcher() {
    final RequestMatcher pathGetMatcher = new AntPathRequestMatcher(endpointUrl, HttpMethod.GET.name(), false);
    final RequestMatcher clientIdMatcher = request -> StringUtils.hasText(request.getParameter(
        OAuth2ParameterNames.CLIENT_ID));
    final RequestMatcher redirectUriMatcher = request -> StringUtils.hasText(request.getParameter(OAuth2ParameterNames.REDIRECT_URI));
    final RequestMatcher responseTypeMatcher = request -> StringUtils.hasText(request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE));
    final RequestMatcher openidMatcher = request -> {
      final var scopes = StringUtils.hasText(request.getParameter(OAuth2ParameterNames.SCOPE)) ?
        request.getParameter(OAuth2ParameterNames.SCOPE): null;
      return scopes != null && scopes.contains(OidcScopes.OPENID);
    };

    return new AndRequestMatcher(pathGetMatcher,
        clientIdMatcher,
        redirectUriMatcher,
        responseTypeMatcher,
        openidMatcher);
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {
    if (!this.requestMatcher.matches(request)) {
      filterChain.doFilter(request, response);
      return;
    }

    // parse OAuth2 parameters
    Authentication authentication = this.authenticationConverter.convert(request);

    if (authentication == null) {
      SecurityContextHolder.getContext().setAuthentication(ANONYMOUS_AUTHENTICATION);
      // we can safely discard the parsed params, because they will be avaialble at the FederatedAuthenticationEntryPoint
      // in a request object
      filterChain.doFilter(request, response);
      return;
    }

    // if the user is not authenticated redirect to login page
    if (authentication instanceof OAuth2WebFlowConsentAuthentication consentAuth && consentAuth.requiresConsent()) {
      // TODO: redirect to consent page with all request params
    } else {
      // TODO: issue code and return to the client
    }
  }
}
