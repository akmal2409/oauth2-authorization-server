package com.akmal.oauth2authorizationserver.crypto.jwt;

public record Claim(
    String name,
    Object value
) {
}
