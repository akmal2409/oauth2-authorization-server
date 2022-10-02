package com.akmal.oauth2authorizationserver.config;

import com.akmal.oauth2authorizationserver.idgen.Generator;
import com.akmal.oauth2authorizationserver.internal.security.authentication.WebAuthenticationDetailsSource;
import com.akmal.oauth2authorizationserver.internal.security.filter.CustomUsernamePasswordAuthenticationFilter;
import com.akmal.oauth2authorizationserver.oauth2.authprovider.OAuth2WebFlowRequestAuthenticationProvider;
import com.akmal.oauth2authorizationserver.repository.ScopeRepository;
import com.akmal.oauth2authorizationserver.repository.SessionRepository;
import com.akmal.oauth2authorizationserver.repository.UserGrantedClientRepository;
import com.akmal.oauth2authorizationserver.repository.UserRepository;
import com.akmal.oauth2authorizationserver.repository.client.ClientRepository;
import com.akmal.oauth2authorizationserver.service.v1.auth.UserCredentialsAuthenticationProvider;
import com.akmal.oauth2authorizationserver.web.filter.oauth2.FederatedAuthenticationEntryPoint;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

@Configuration
@RequiredArgsConstructor
public class AuthenticationConfiguration {
  private final AuthenticationProperties authProps;


  @Bean
  CustomUsernamePasswordAuthenticationFilter usernamePasswordAuthenticationFilter(
      AuthenticationManager authenticationManager
  ) {
    final var filter = new CustomUsernamePasswordAuthenticationFilter(authenticationManager,
        new WebAuthenticationDetailsSource());
    filter.setFilterProcessesUrl(this.authProps.getLoginProcessUrl());
    filter.setAuthenticationManager(authenticationManager);
    filter.setAuthenticationSuccessHandler(this.authenticationSuccessHandler());
    return filter;
  }

  @Bean
  AuthenticationEntryPoint federatedAuthenticationEntryPoint() {
    return new FederatedAuthenticationEntryPoint(new LoginUrlAuthenticationEntryPoint(this.authProps.getLoginUrl()),
        new DefaultRedirectStrategy());
  }

  @Bean
  UserCredentialsAuthenticationProvider userCredentialsCookieAuthProvider(UserRepository userRepository,
      PasswordEncoder passwordEncoder, Generator<String> idGenerator,
      SessionRepository sessionRepository, AuthenticationProperties authenticationProperties) {
    return new UserCredentialsAuthenticationProvider(userRepository, sessionRepository, passwordEncoder, idGenerator, authenticationProperties.getCookieExpirationTime());
  }

  @Bean
  AuthenticationSuccessHandler authenticationSuccessHandler() {
    return new com.akmal.oauth2authorizationserver.web.filter.oauth2.AuthenticationSuccessHandler();
  }

  @Bean
  OAuth2WebFlowRequestAuthenticationProvider oAuth2WebFlowRequestAuthenticationProvider(
      ClientRepository clientRepository,
      UserGrantedClientRepository userGrantedClientRepository,
      ScopeRepository scopeRepository
  ) {
    return new OAuth2WebFlowRequestAuthenticationProvider(
        clientRepository, userGrantedClientRepository,
        scopeRepository
    );
  }
}
