package com.akmal.oauth2authorizationserver.validator;

import org.apache.commons.validator.routines.UrlValidator;

public class ApacheCommonsUrlValidatorAdapter implements Validator<String> {

  private final UrlValidator urlValidator;

  public ApacheCommonsUrlValidatorAdapter(UrlValidator urlValidator) {
    this.urlValidator = urlValidator;
  }

  @Override
  public boolean validate(String s) {
    return this.urlValidator.isValid(s);
  }
}
