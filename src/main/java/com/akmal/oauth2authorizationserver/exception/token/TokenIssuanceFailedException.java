package com.akmal.oauth2authorizationserver.exception.token;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
public class TokenIssuanceFailedException extends RuntimeException {

  public TokenIssuanceFailedException(String message) {
    super(message);
  }

  public TokenIssuanceFailedException(String message, Throwable cause) {
    super(message, cause);
  }

  public TokenIssuanceFailedException(Throwable cause) {
    super(cause);
  }

  protected TokenIssuanceFailedException(String message, Throwable cause, boolean enableSuppression,
      boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }
}
