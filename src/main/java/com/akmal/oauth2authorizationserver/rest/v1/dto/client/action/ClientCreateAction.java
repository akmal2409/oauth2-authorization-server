package com.akmal.oauth2authorizationserver.rest.v1.dto.client.action;

import com.akmal.oauth2authorizationserver.model.client.Client;
import com.akmal.oauth2authorizationserver.model.client.Grant;
import com.akmal.oauth2authorizationserver.model.client.GrantType;
import java.util.List;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

public record ClientCreateAction(
    @NotNull String name,
    @NotNull @NotEmpty List<String> grants,
    @NotNull List<String> signInRedirectUris,
    @NotNull List<String> signOutRedirectUris,
    @NotNull List<String> trustedOrigins,
    boolean requireUserConsent,
    boolean allowWildcardsInRedirectUrls
) {

  public Client toClient() {
    return new Client(
        null,
        this.name,
        null,
        this.grants.stream().map(GrantType::valueOf).map(Grant::new).toList(),
        this.signInRedirectUris,
        this.signOutRedirectUris,
        this.trustedOrigins,
        this.requireUserConsent,
        this.allowWildcardsInRedirectUrls,
        List.of(),
        List.of(),
        false
    );
  }
}
