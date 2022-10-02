package com.akmal.oauth2authorizationserver.oauth2;

import com.akmal.oauth2authorizationserver.oauth2.authentication.OAuth2WebFlowAuthenticationDetails;
import javax.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AuthenticationDetailsSource;

public class OAuth2WebFlowAuthenticationDetailsSource
    implements AuthenticationDetailsSource<HttpServletRequest, OAuth2WebFlowAuthenticationDetails> {

  @Override
  public OAuth2WebFlowAuthenticationDetails buildDetails(HttpServletRequest context) {
    return new OAuth2WebFlowAuthenticationDetails(context);
  }
}
