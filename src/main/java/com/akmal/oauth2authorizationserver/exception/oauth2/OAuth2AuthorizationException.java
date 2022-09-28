package com.akmal.oauth2authorizationserver.exception.oauth2;

import com.akmal.oauth2authorizationserver.oauth2.OAuth2Error;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class OAuth2AuthorizationException extends RuntimeException {
  private final OAuth2Error error;

  public OAuth2AuthorizationException(OAuth2Error error) {
    this.error = error;
  }

  public OAuth2Error getError() {
    return error;
  }
}
