package com.akmal.oauth2authorizationserver.exception.crypto;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
public class JwtCreationException extends RuntimeException {

  public JwtCreationException(String message) {
    super(message);
  }

  public JwtCreationException(String message, Throwable cause) {
    super(message, cause);
  }

  public JwtCreationException(Throwable cause) {
    super(cause);
  }

  public JwtCreationException(String message, Throwable cause, boolean enableSuppression,
      boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }
}
