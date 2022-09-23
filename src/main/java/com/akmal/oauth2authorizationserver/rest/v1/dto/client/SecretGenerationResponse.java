package com.akmal.oauth2authorizationserver.rest.v1.dto.client;

public record SecretGenerationResponse(
    String clientId,
    String clientSecret
) {

}
