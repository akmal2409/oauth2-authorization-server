package com.akmal.oauth2authorizationserver.exception.validation;

public class MissingAttributeException extends AbstractValidationException {

  public MissingAttributeException(String attribute) {
    super(String.format("Missing attribute %s", attribute));
  }
}
