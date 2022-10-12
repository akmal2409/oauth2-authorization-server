package com.akmal.oauth2authorizationserver.oauth2.token.issuance;

import com.akmal.oauth2authorizationserver.model.client.GrantType;
import java.util.List;

public record OAuth2TokenIssueProperties(
    String sub,
    String clientId,
    List<String> scopes,
    GrantType grantType
) {

}
