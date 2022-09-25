package com.akmal.oauth2authorizationserver.exception.validation.authentication;

import com.akmal.oauth2authorizationserver.exception.validation.AbstractValidationException;

public class MalformedAuthenticationAttributeException extends AbstractValidationException {

  public MalformedAuthenticationAttributeException(String expected, String actual,
      Throwable ex) {
    super(expected, actual, ex);
  }
}
