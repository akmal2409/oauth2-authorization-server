package com.akmal.oauth2authorizationserver.config.authentication;

/**
 * Defines constants (mappings) for authentication attributes to assist extraction and serialization.
 */
public class AuthenticationAttributes {

  public static final String CLIENT_ID = "client_id";
  public static final String REDIRECT_URI = "redirect_uri";
  public static final String RESPONSE_TYPE = "response_type";
  public static final String STATE = "state";
  public static final String CODE_CHALLENGE = "code_challenge";
  public static final String CODE_CHALLENGE_METHOD = "code_challenge_method";
  public static final String NONCE = "nonce";
  public static final String IDP = "idp";
  public static final String IDP_SCOPE = "idp_scope";
  public static final String SCOPE = "scopes";

  private AuthenticationAttributes() {}
}
