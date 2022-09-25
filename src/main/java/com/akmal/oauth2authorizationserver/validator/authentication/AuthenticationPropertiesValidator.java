package com.akmal.oauth2authorizationserver.validator.authentication;

import com.akmal.oauth2authorizationserver.config.authentication.AuthenticationAttributes;
import com.akmal.oauth2authorizationserver.exception.validation.MissingAttributeException;
import com.akmal.oauth2authorizationserver.exception.validation.authentication.MalformedAuthenticationAttributeException;
import com.akmal.oauth2authorizationserver.model.authentication.AuthenticationProperties;
import com.akmal.oauth2authorizationserver.validator.Validator;
import java.util.List;
import org.springframework.util.StringUtils;

public class AuthenticationPropertiesValidator implements Validator<AuthenticationProperties> {
  private final Validator<String> urlValidator;
  private static final List<String> REQUIRED_ATTRIBUTES = List.of(
      AuthenticationAttributes.CLIENT_ID,
      AuthenticationAttributes.REDIRECT_URI,
      AuthenticationAttributes.RESPONSE_TYPE
  );

  private static final List<String> VALID_URLS = List.of(
      AuthenticationAttributes.REDIRECT_URI
  );

  private static final List<String> VALID_COLLECTIONS = List.of(
      AuthenticationAttributes.IDP_SCOPE,
      AuthenticationAttributes.SCOPE
  );

  public AuthenticationPropertiesValidator(Validator<String> urlValidator) {
    this.urlValidator = urlValidator;
  }

  /**
   * Validates required attributes, if the URLs are present it validates them too,
   * the same applies to comma separated collections.
   * @param attributes map of attributes.
   * @return validity.
   */
  @Override
  public boolean validate(AuthenticationProperties attributes) {
    this.validateRequiredAttributes(attributes);

    if (!this.urlValidator.validate(attributes.redirectUri())) {
      throw new MalformedAuthenticationAttributeException("valid url", attributes.redirectUri(), null);
    }

    if (StringUtils.hasText(attributes.codeChallenge()) &&
    attributes.codeChallengeMethod() == null) {
      throw new MissingAttributeException("code_challenge_method");
    }

    return true;
  }


  private void validateRequiredAttributes(AuthenticationProperties props) {
    if (!StringUtils.hasText(props.clientId())) {
      throw new MissingAttributeException("client_id");
    }

    if (!StringUtils.hasText(props.redirectUri())) {
      throw new MissingAttributeException("redirect_uri");
    }

    if (props.responseType() == null) {
      throw new MissingAttributeException("response_type");
    }
  }
}
