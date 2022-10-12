package com.akmal.oauth2authorizationserver.config;

import com.akmal.oauth2authorizationserver.crypto.RsaKeyService;
import com.akmal.oauth2authorizationserver.oauth2.authorization.strategy.GrantBasedAuthorizationStrategyFactory;
import com.akmal.oauth2authorizationserver.oauth2.authprovider.OAuth2WebFlowRequestAuthenticationProvider;
import com.akmal.oauth2authorizationserver.oauth2.authprovider.token.AuthorizationCodeTokenAuthenticationProvider;
import com.akmal.oauth2authorizationserver.oauth2.authprovider.token.RefreshTokenAuthenticationProvider;
import com.akmal.oauth2authorizationserver.oauth2.token.issuance.TokenIssueService;
import com.akmal.oauth2authorizationserver.oauth2.web.filter.oauth2.OAuth2AuthorizationEndpointFilter;
import com.akmal.oauth2authorizationserver.oauth2.web.filter.oauth2.OAuth2TokenRequestFilter;
import com.akmal.oauth2authorizationserver.repository.OAuth2AuthCodePendingRequestRepository;
import com.akmal.oauth2authorizationserver.repository.RefreshTokenRepository;
import com.akmal.oauth2authorizationserver.repository.ScopeRepository;
import com.akmal.oauth2authorizationserver.repository.UserGrantedClientRepository;
import com.akmal.oauth2authorizationserver.repository.client.ClientRepository;
import com.akmal.oauth2authorizationserver.shared.persistence.TransactionPropagator;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.security.authentication.AuthenticationManager;

/**
 * Configuration class that exposes the beans to the Spring Context, which are related
 * to oauth2 flow. This beans include filters for initial authorization as well as components that issue tokens
 * and introspect them.
 */
@Configuration
public class OAuth2AuthorizationConfiguration {


  @Bean
  OAuth2WebFlowRequestAuthenticationProvider oAuth2WebFlowRequestAuthenticationProvider(
      ClientRepository clientRepository,
      UserGrantedClientRepository userGrantedClientRepository,
      ScopeRepository scopeRepository,
      TransactionPropagator transactionPropagator
  ) {
    return new OAuth2WebFlowRequestAuthenticationProvider(
        clientRepository, userGrantedClientRepository,
        scopeRepository,
        transactionPropagator);
  }

  @Bean
  AuthorizationCodeTokenAuthenticationProvider authorizationCodeTokenAuthenticationProvider(
      OAuth2AuthCodePendingRequestRepository repository
  ) {
    return new AuthorizationCodeTokenAuthenticationProvider(repository);
  }

  @Bean
  RefreshTokenAuthenticationProvider refreshTokenAuthenticationProvider(RefreshTokenRepository refreshTokenRepository) {
    return new RefreshTokenAuthenticationProvider(refreshTokenRepository);
  }

  @Bean
  @DependsOn("grantBasedAuthorizationStrategiesConfiguration")
  OAuth2AuthorizationEndpointFilter oAuth2AuthorizationEndpointFilter(AuthenticationManager authenticationManager,
      @Qualifier("grantBasedAuthorizationStrategyFactory") GrantBasedAuthorizationStrategyFactory grantBasedAuthorizationStrategyFactory) {
    return new OAuth2AuthorizationEndpointFilter(authenticationManager, grantBasedAuthorizationStrategyFactory);
  }

  @Bean
  OAuth2TokenRequestFilter oAuth2TokenRequestFilter(AuthenticationManager authenticationManager,
      TokenIssueService tokenIssueService, ObjectMapper objectMapper) {
    return new OAuth2TokenRequestFilter(authenticationManager, tokenIssueService, objectMapper);
  }
}
