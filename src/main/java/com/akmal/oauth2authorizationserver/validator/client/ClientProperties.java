package com.akmal.oauth2authorizationserver.validator.client;

import com.akmal.oauth2authorizationserver.rest.v1.dto.client.action.ClientCreateAction;
import com.akmal.oauth2authorizationserver.rest.v1.dto.client.action.ClientUpdateAction;
import java.util.Collection;

public record ClientProperties(
    String name,
    Collection<String> grants,
    Collection<String> systemWhitelistedGrants,
    Collection<String> signInRedirectUris,
    Collection<String> signOutRedirectUris,
    Collection<String> trustedOrigins,
    boolean allowWildcardsInRedirectUrls
) {

  public static ClientProperties from(ClientCreateAction createAction, Collection<String> systemWhitelistedGrants) {
    return new ClientProperties(
        createAction.name(),
        createAction.grants(),
        systemWhitelistedGrants,
        createAction.signInRedirectUris(),
        createAction.signOutRedirectUris(),
        createAction.trustedOrigins(),
        createAction.allowWildcardsInRedirectUrls()
    );
  }

  public static ClientProperties from(ClientUpdateAction updateAction, Collection<String> systemWhitelistedGrants) {
    return new ClientProperties(
        updateAction.name(),
        updateAction.grants(),
        systemWhitelistedGrants,
        updateAction.signInRedirectUris(),
        updateAction.signOutRedirectUris(),
        updateAction.trustedOrigins(),
        updateAction.allowWildcardsInRedirectUrls()
    );
  }
}
