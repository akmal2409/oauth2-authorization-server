package com.akmal.oauth2authorizationserver.exception.validation;

public class InvalidScopeConfigurationException extends AbstractValidationException {

  public InvalidScopeConfigurationException(String expected, String actual, Throwable ex) {
    super(expected, actual, ex);
  }

  public InvalidScopeConfigurationException(String expected, String actual) {
    super(expected, actual, null);
  }

}
