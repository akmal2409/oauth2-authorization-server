package com.akmal.oauth2authorizationserver.oauth2.authorization.strategy;

import com.akmal.oauth2authorizationserver.oauth2.authentication.OAuth2WebFlowRequestAuthentication;
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Defines a common contract for implementations that handles the authorization flow based on the grant specified by client.
 */
public interface GrantBasedAuthorizationStrategy {

  /**
   * The implementation must proceed with authorization based on the type of grant.
   * For example in the case of Authorization Code Grant the service implementation must generate the code, persist it and send it back to the client.
   * @param authentication parsed OAuth2 attributes
   * @param request http request
   * @param response http response
   */
  void handle(OAuth2WebFlowRequestAuthentication authentication, HttpServletRequest request, HttpServletResponse response)
      throws IOException;
}
