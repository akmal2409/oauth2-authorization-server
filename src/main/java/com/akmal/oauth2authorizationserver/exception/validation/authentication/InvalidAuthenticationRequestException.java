package com.akmal.oauth2authorizationserver.exception.validation.authentication;

import com.akmal.oauth2authorizationserver.exception.validation.AbstractValidationException;

public class InvalidAuthenticationRequestException extends AbstractValidationException {

  public InvalidAuthenticationRequestException(String message) {
    super(message);
  }
}
