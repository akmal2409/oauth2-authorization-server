package com.akmal.oauth2authorizationserver.config;

import com.akmal.oauth2authorizationserver.model.authentication.AuthenticationProperties;
import com.akmal.oauth2authorizationserver.validator.ApacheCommonsUrlValidatorAdapter;
import com.akmal.oauth2authorizationserver.validator.Validator;
import com.akmal.oauth2authorizationserver.validator.authentication.AuthenticationPropertiesValidator;
import org.apache.commons.validator.routines.UrlValidator;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ValidationConfiguration {


  @Bean
  Validator<String> httpUrlValidator() {
    return new ApacheCommonsUrlValidatorAdapter(new UrlValidator(new String[]{"http", "https"}));
  }

  @Bean
  Validator<AuthenticationProperties> authenticationPropertiesValidator(
      @Qualifier("httpUrlValidator") Validator<String> urlValidator
  ) {
    return new AuthenticationPropertiesValidator(urlValidator);
  }
}
