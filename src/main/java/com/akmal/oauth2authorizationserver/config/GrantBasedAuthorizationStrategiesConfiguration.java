package com.akmal.oauth2authorizationserver.config;

import com.akmal.oauth2authorizationserver.oauth2.authorization.strategy.AuthorizationCodeStrategy;
import com.akmal.oauth2authorizationserver.oauth2.authorization.strategy.GrantBasedAuthorizationStrategyFactory;
import com.akmal.oauth2authorizationserver.repository.OAuth2AuthCodePendingRequestRepository;
import com.akmal.oauth2authorizationserver.shared.persistence.TransactionPropagator;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.beans.factory.config.ServiceLocatorFactoryBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;

@Configuration
public class GrantBasedAuthorizationStrategiesConfiguration {

  @Bean
  public FactoryBean grantBasedAuthorizationStrategyFactory() {
    final var factoryBean = new ServiceLocatorFactoryBean();
    factoryBean.setServiceLocatorInterface(GrantBasedAuthorizationStrategyFactory.class);
    return factoryBean;
  }

  @Bean(name = "authorizationCodeStrategy")
  @Scope(scopeName = ConfigurableBeanFactory.SCOPE_PROTOTYPE)
  AuthorizationCodeStrategy authorizationCodeStrategy(
      OAuth2AuthCodePendingRequestRepository repository,
      TransactionPropagator transactionPropagator
  ) {
    return new AuthorizationCodeStrategy(repository, transactionPropagator);
  }

}
