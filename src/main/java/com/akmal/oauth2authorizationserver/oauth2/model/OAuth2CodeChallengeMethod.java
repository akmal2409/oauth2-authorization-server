package com.akmal.oauth2authorizationserver.oauth2.model;

/**
 * Represents the hashing algorithm that should be used
 * during PKCE flow of verifying the code_verifier.
 */
public enum OAuth2CodeChallengeMethod {
  S256("SHA-256");

  private String name;

  OAuth2CodeChallengeMethod(String name) {
    this.name = name;
  }

  public String getName() {
    return name;
  }

  public static OAuth2CodeChallengeMethod from(String name) {
    for (OAuth2CodeChallengeMethod method: values()) {
      if (method.toString().equalsIgnoreCase(name)) return method;
    }

    return null;
  }
}
