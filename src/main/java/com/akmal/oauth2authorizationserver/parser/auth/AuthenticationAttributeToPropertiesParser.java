package com.akmal.oauth2authorizationserver.parser.auth;

import com.akmal.oauth2authorizationserver.config.authentication.AuthenticationAttributes;
import com.akmal.oauth2authorizationserver.model.authentication.AuthResponseType;
import com.akmal.oauth2authorizationserver.model.authentication.AuthenticationProperties;
import com.akmal.oauth2authorizationserver.model.authentication.CodeChallengeMethod;
import com.akmal.oauth2authorizationserver.parser.Parser;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class AuthenticationAttributeToPropertiesParser implements Parser<Map<String, String>, AuthenticationProperties> {

  @Override
  public AuthenticationProperties parse(Map<String, String> attributes) {
    return new AuthenticationProperties(
        attributes.get(AuthenticationAttributes.CLIENT_ID),
        attributes.get(AuthenticationAttributes.REDIRECT_URI),
        wrapValue(attributes.get(AuthenticationAttributes.RESPONSE_TYPE), AuthResponseType::from),
        attributes.get(AuthenticationAttributes.STATE),
        attributes.get(AuthenticationAttributes.CODE_CHALLENGE),
        wrapValue(attributes.get(AuthenticationAttributes.CODE_CHALLENGE_METHOD), CodeChallengeMethod::from),
        attributes.get(AuthenticationAttributes.NONCE),
        attributes.get(AuthenticationAttributes.IDP),
        extractCollection(attributes.get(AuthenticationAttributes.IDP_SCOPE), ","),
        extractCollection(attributes.get(AuthenticationAttributes.SCOPE), ",")
    );
  }

  private <T> T wrapValue(String value, Function<String, T> mapper) {
    if (value == null) return null;
    return mapper.apply(value);
  }
  private List<String> extractCollection(String value, String delimiter) {
    if (!StringUtils.hasText(value)) return new ArrayList<>();

    return Arrays.asList(value.split(delimiter));
  }
}
