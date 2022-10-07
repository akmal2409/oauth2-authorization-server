package com.akmal.oauth2authorizationserver.config;

import com.akmal.oauth2authorizationserver.oauth2.authprovider.OAuth2WebFlowRequestAuthenticationProvider;
import com.akmal.oauth2authorizationserver.oauth2.web.filter.oauth2.OAuth2AuthorizationEndpointFilter;
import com.akmal.oauth2authorizationserver.repository.ScopeRepository;
import com.akmal.oauth2authorizationserver.repository.UserGrantedClientRepository;
import com.akmal.oauth2authorizationserver.repository.client.ClientRepository;
import com.akmal.oauth2authorizationserver.shared.persistence.TransactionPropagator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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
  OAuth2AuthorizationEndpointFilter oAuth2AuthorizationEndpointFilter(AuthenticationManager authenticationManager) {
    return new OAuth2AuthorizationEndpointFilter(authenticationManager);
  }
}
