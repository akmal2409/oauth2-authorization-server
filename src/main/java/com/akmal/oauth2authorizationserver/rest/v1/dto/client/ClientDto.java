package com.akmal.oauth2authorizationserver.rest.v1.dto.client;

import com.akmal.oauth2authorizationserver.model.client.Client;
import java.util.List;
import java.util.Optional;

public record ClientDto(
    String clientId,
    String name,
    List<String> grants,
    List<String> signInRedirectUris,
    List<String> signOutRedirectUris,
    List<String> trustedOrigins,
    boolean requireUserConsent,
    boolean allowWildcardsInRedirectUrls
) {

  public static ClientDto from(Client client) {
    return new ClientDto(
        client.getClientId(),
        client.getName(),
        Optional.ofNullable(client.getGrants())
            .map(gs -> gs.stream().map(g -> g.getType().toString())
                           .toList())
            .orElse(List.of()),
        Optional.ofNullable(client.getSignInRedirectUris()).orElse(List.of()),
        Optional.ofNullable(client.getSignOutRedirectUris()).orElse(List.of()),
        Optional.ofNullable(client.getTrustedOrigins()).orElse(List.of()),
        client.isRequireUserConsent(),
        client.isAllowWildcardsInRedirectUrls()
    );
  }
}
