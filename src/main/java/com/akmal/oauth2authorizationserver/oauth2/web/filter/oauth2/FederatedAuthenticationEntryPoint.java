package com.akmal.oauth2authorizationserver.oauth2.web.filter.oauth2;

import com.akmal.oauth2authorizationserver.oauth2.AuthenticationHttpSessionAttributes;
import com.akmal.oauth2authorizationserver.oauth2.config.OAuth2ParameterNames;
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.util.StringUtils;

/**
 * The class serves a purpose as the last component in the filter chain when the authentication fails
 * and is invoked just before sending the exception to the user. It is used to redirect the user
 * to the login page or in case if the idp query paramter is present, it will redirect to the respective
 * 3rd party Idp.
 */
@Slf4j
public class FederatedAuthenticationEntryPoint implements AuthenticationEntryPoint {

  private final AuthenticationEntryPoint webBasedLoginEntryPoint;
  private final RedirectStrategy redirectStrategy;

  public FederatedAuthenticationEntryPoint(AuthenticationEntryPoint webBasedLoginEntryPoint,
      RedirectStrategy redirectStrategy) {
    this.webBasedLoginEntryPoint = webBasedLoginEntryPoint;
    this.redirectStrategy = redirectStrategy;
  }

  @Override
  public void commence(HttpServletRequest request, HttpServletResponse response,
      AuthenticationException authException) throws IOException, ServletException {
    final var idp = request.getParameter(OAuth2ParameterNames.IDP);
    if (StringUtils.hasText(idp)) {
      // federate the authentication to the 3rd party Idp after validation
      response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "External IDP authentication is not implemented");
    } else {
      // redirect user to the login page with the targetUrl query parameter set to the request url
      final var targetUrl = RequestUtils.getFullRequestUrl(request);
      request.getSession().setAttribute(AuthenticationHttpSessionAttributes.TARGET_URL, targetUrl);
      this.webBasedLoginEntryPoint.commence(request, response, authException);
    }
  }

}
