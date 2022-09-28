package com.akmal.oauth2authorizationserver.oauth2;

import com.fasterxml.jackson.annotation.JsonProperty;

public record OAuth2Error(
    String error,
    @JsonProperty("error_description") String errorDescription,
    @JsonProperty("error_uri") String errorUri,
    String state
) {

}
