package com.akmal.oauth2authorizationserver.model.authentication;

/**
 * Represents the hashing algorithm that should be used
 * during PKCE flow of verifying the code_verifier.
 */
public enum CodeChallengeMethod {
  S256;

  public static CodeChallengeMethod from(String name) {
    for (CodeChallengeMethod method: values()) {
      if (method.toString().equalsIgnoreCase(name)) return method;
    }

    return null;
  }
}
