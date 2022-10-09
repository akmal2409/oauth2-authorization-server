package com.akmal.oauth2authorizationserver.exception.crypto;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
public class KeyNotAvailableException extends RuntimeException {

  public KeyNotAvailableException(String message) {
    super(message);
  }

  public KeyNotAvailableException(String message, Throwable cause) {
    super(message, cause);
  }

  public KeyNotAvailableException(Throwable cause) {
    super(cause);
  }

  protected KeyNotAvailableException(String message, Throwable cause, boolean enableSuppression,
      boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }
}
