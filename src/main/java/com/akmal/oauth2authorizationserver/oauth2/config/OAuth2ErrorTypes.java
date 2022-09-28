package com.akmal.oauth2authorizationserver.oauth2.config;

public class OAuth2ErrorTypes {

  private OAuth2ErrorTypes() {}

  public static final String INVALID_REQUEST = "invalid_request";
  public static final String UNAUTHORIZED_CLIENT = "unauthorized_client";
  public static final String ACCESS_DENIED = "access_denied";
  public static final String UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type";
  public static final String INVALID_SCOPE = "invalid_scope";
  public static final String SERVER_ERROR = "server_error";
  public static final String TEMPORARILY_UNAVAILABLE = "temporarily_unavailable";
}
