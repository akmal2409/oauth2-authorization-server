package com.akmal.oauth2authorizationserver.oauth2.web.filter.oauth2;

import com.akmal.oauth2authorizationserver.oauth2.authconverter.OAuth2TokenRequestAuthenticationConverter;
import com.akmal.oauth2authorizationserver.oauth2.authentication.token.OAuth2TokenRequestAuthentication;
import com.akmal.oauth2authorizationserver.oauth2.token.issuance.OAuth2TokenIssueProperties;
import com.akmal.oauth2authorizationserver.oauth2.token.issuance.TokenIssueService;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * The filter represents the /token endpoint stated in the OAuth2 specification that returns an access, id or refresh_token or all together
 * based on the parameters.
 */
public class OAuth2TokenRequestFilter extends OncePerRequestFilter {
  private final RequestMatcher requestMatcher;
  private final AuthenticationConverter authenticationConverter;
  private final AuthenticationManager authenticationManager;
  private final TokenIssueService tokenIssueService;
  private final ObjectMapper objectMapper;


  public OAuth2TokenRequestFilter(AuthenticationManager authenticationManager,
      TokenIssueService tokenIssueService, ObjectMapper objectMapper) {
    this.authenticationManager = authenticationManager;
    this.tokenIssueService = tokenIssueService;
    this.objectMapper = objectMapper;
    this.requestMatcher = new AntPathRequestMatcher("/oauth2/token", HttpMethod.POST.name(), false);
    this.authenticationConverter = new OAuth2TokenRequestAuthenticationConverter();
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {
    if (!requestMatcher.matches(request)) {
      filterChain.doFilter(request, response);
      return;
    }

    final Authentication tokenRequestAuthentication = this.authenticationConverter.convert(request);

    if (tokenRequestAuthentication == null) {
      filterChain.doFilter(request, response);
      return;
    }

    final OAuth2TokenRequestAuthentication validatedAuthentication = (OAuth2TokenRequestAuthentication) this.authenticationManager.authenticate(tokenRequestAuthentication);

    if (!validatedAuthentication.isAuthenticated()) {
      filterChain.doFilter(request, response);
      return;
    }

    this.issueToken(validatedAuthentication, response);
  }

  private void issueToken(OAuth2TokenRequestAuthentication authentication,
      HttpServletResponse response) {
    final var tokenSet = this.tokenIssueService.issueTokenSet(new OAuth2TokenIssueProperties(
        authentication.getSub(), authentication.getClientId(), authentication.getGrantedScopes(), authentication.getGrantType()
    ));

    response.setStatus(200);
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);

    try (final var writer = response.getWriter()) {
      writer.write(this.objectMapper.writeValueAsString(tokenSet));
      writer.flush();
    } catch (IOException ignore) {}
  }
}
