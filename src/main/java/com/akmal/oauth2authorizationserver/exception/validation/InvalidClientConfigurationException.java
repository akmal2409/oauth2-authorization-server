package com.akmal.oauth2authorizationserver.exception.validation;

public class InvalidClientConfigurationException extends AbstractValidationException {

  public InvalidClientConfigurationException(String expected, String actual, Throwable ex) {
    super(expected, actual, ex);
  }

  public InvalidClientConfigurationException(String expected, String actual) {
    super(expected, actual, null);
  }

  public InvalidClientConfigurationException(String message) {
    super(message);
  }
}
