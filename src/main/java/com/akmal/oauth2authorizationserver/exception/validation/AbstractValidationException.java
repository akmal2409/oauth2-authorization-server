package com.akmal.oauth2authorizationserver.exception.validation;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public abstract class AbstractValidationException extends RuntimeException {
  private static final String DEFAULT_ERROR_MSG_TEMPLATE =
      "A validation error occurred. Expected: {expected_value}. Received: {actual_value}";
  protected String expected;
  protected String actual;


  protected AbstractValidationException(String expected, String actual, Throwable ex) {
    super(DEFAULT_ERROR_MSG_TEMPLATE
              .replace("{expected_value}", expected)
              .replace("{actual_value}", actual), ex, false, true);

    this.expected = expected;
    this.actual = actual;

  }

  protected AbstractValidationException(String message) {
    super(message);
  }

  public String getActual() {
    return actual;
  }

  public String getExpected() {
    return expected;
  }
}
