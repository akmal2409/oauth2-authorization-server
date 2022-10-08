package com.akmal.oauth2authorizationserver.oauth2.web.filter.oauth2;

import com.akmal.oauth2authorizationserver.model.client.Scope;
import com.akmal.oauth2authorizationserver.oauth2.OAuth2WebFlowAuthenticationDetailsSource;
import com.akmal.oauth2authorizationserver.oauth2.authconverter.OAuth2WebFlowRequestAuthenticationConverter;
import com.akmal.oauth2authorizationserver.oauth2.authentication.OAuth2WebFlowAuthenticationDetails;
import com.akmal.oauth2authorizationserver.oauth2.authentication.OAuth2WebFlowConsentAuthentication;
import com.akmal.oauth2authorizationserver.oauth2.authentication.OAuth2WebFlowRequestAuthentication;
import com.akmal.oauth2authorizationserver.oauth2.authorization.strategy.GrantBasedAuthorizationStrategyFactory;
import com.akmal.oauth2authorizationserver.oauth2.authorization.strategy.GrantBasedAuthorizationStrategyType;
import java.io.IOException;
import java.util.List;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

@Slf4j
public class OAuth2AuthorizationEndpointFilter extends OncePerRequestFilter {
  private static final String DEFAULT_AUTHORIZATION_ENDPOINT_URL = "/oauth2/authorize";
  private static final String DEFAULT_CONSENT_PAGE_URL = "/consent";
  private static final Authentication ANONYMOUS_AUTHENTICATION = new AnonymousAuthenticationToken(
      "anonymous", "anonymousUser", List.of(new SimpleGrantedAuthority("ROLE_ANONYMOUS"))
  );
  private final RequestMatcher requestMatcher;
  private final String endpointUrl;
  private final String consentUrl;
  private final AuthenticationConverter authenticationConverter;
  private final RedirectStrategy redirectStrategy;
  private final AuthenticationDetailsSource<HttpServletRequest, OAuth2WebFlowAuthenticationDetails> detailsSource;
  private final AuthenticationManager authenticationManager;
  private final GrantBasedAuthorizationStrategyFactory grantBasedAuthStrategyFactory;

  public OAuth2AuthorizationEndpointFilter(String endpointUrl, String consentUrl, RedirectStrategy redirectStrategy,
      AuthenticationManager authenticationManager,
      GrantBasedAuthorizationStrategyFactory grantBasedAuthStrategyFactory) {
    this.endpointUrl = endpointUrl;
    this.consentUrl = consentUrl;
    this.redirectStrategy = redirectStrategy;
    this.requestMatcher = new AntPathRequestMatcher(endpointUrl, HttpMethod.GET.name(), false);
    this.grantBasedAuthStrategyFactory = grantBasedAuthStrategyFactory;
    this.detailsSource = new OAuth2WebFlowAuthenticationDetailsSource();
    this.authenticationConverter = new OAuth2WebFlowRequestAuthenticationConverter(this.detailsSource);
    this.authenticationManager = authenticationManager;
  }

  public OAuth2AuthorizationEndpointFilter(AuthenticationManager authenticationManager, GrantBasedAuthorizationStrategyFactory grantBasedAuthStrategyFactory) {
    this(DEFAULT_AUTHORIZATION_ENDPOINT_URL, DEFAULT_CONSENT_PAGE_URL, new DefaultRedirectStrategy(), authenticationManager,
        grantBasedAuthStrategyFactory);
  }

  @Override
  protected void doFilterInternal(@NotNull HttpServletRequest request, @NotNull HttpServletResponse response,
      @NotNull FilterChain filterChain) throws ServletException, IOException {
    if (!this.requestMatcher.matches(request)) {
      filterChain.doFilter(request, response);
      return;
    }

    // parse OAuth2 parameters
    Authentication authentication = this.authenticationConverter.convert(request);
    log.debug("remote_ip={};event=oauth2_authorization_request;message=Received OAuth2 authorization request;params={}", request.getRemoteAddr(),
        authentication);

    if (authentication == null || !authentication.isAuthenticated()) {
      SecurityContextHolder.getContext().setAuthentication(ANONYMOUS_AUTHENTICATION);
      // we can safely discard the parsed params, because they will be avaialble at the FederatedAuthenticationEntryPoint
      // in a request object
      filterChain.doFilter(request, response);
      return;
    }

    Authentication validatedAuthentication = this.authenticationManager.authenticate(authentication);

    if (validatedAuthentication instanceof OAuth2WebFlowConsentAuthentication consentAuth && consentAuth.requiresConsent()) {
      this.redirectToConsentPage(request, response, consentAuth.getClientId(), consentAuth.getNotGrantedScopes());
    } else if (validatedAuthentication instanceof OAuth2WebFlowRequestAuthentication requestAuthentication) { // TODO: refactor and return different types of authentications based on grant type
      final var authStrategy = this.grantBasedAuthStrategyFactory.getStrategy(
          GrantBasedAuthorizationStrategyType.AUTHORIZATION_CODE);
      authStrategy.handle(requestAuthentication, request, response);
    } else {
      filterChain.doFilter(request, response);
    }
  }


  private void redirectToConsentPage(HttpServletRequest request, HttpServletResponse response, String clientId, List<Scope> notGrantedScopes)
      throws IOException {
    final var authorizationUrl = RequestUtils.getFullRequestUrl(request);
    final var notGrantedScopeIds = notGrantedScopes.stream().map(Scope::getId).toList();
    final var parameterizedConsentUrl = UriComponentsBuilder.fromPath(this.consentUrl)
                                            .queryParam("client_id", clientId)
                                            .queryParam("grant_scope_ids", notGrantedScopeIds)
                                            .queryParam("target", authorizationUrl)
                                            .toUriString();

    this.redirectStrategy.sendRedirect(request, response, parameterizedConsentUrl);
  }

}
