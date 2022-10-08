package com.akmal.oauth2authorizationserver.oauth2.web.model;

import com.akmal.oauth2authorizationserver.model.client.Scope;
import java.util.List;

public record ConsentRequest(
    List<Scope> grantedScopes,
    List<Scope> pendingScopes,
    String clientName,
    String clientId
) {

}
