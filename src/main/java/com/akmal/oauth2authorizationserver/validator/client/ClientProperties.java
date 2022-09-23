package com.akmal.oauth2authorizationserver.validator.client;

import com.akmal.oauth2authorizationserver.rest.v1.dto.client.action.ClientCreateAction;
import java.util.Collection;
import java.util.List;

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
}
