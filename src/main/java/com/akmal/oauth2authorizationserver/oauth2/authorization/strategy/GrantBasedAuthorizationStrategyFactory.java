package com.akmal.oauth2authorizationserver.oauth2.authorization.strategy;

public interface GrantBasedAuthorizationStrategyFactory {

  GrantBasedAuthorizationStrategy getStrategy(GrantBasedAuthorizationStrategyType type);
}
