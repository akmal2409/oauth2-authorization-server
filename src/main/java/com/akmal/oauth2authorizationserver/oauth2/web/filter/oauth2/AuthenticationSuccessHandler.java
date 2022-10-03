package com.akmal.oauth2authorizationserver.oauth2.web.filter.oauth2;

import com.akmal.oauth2authorizationserver.oauth2.AuthenticationHttpSessionAttributes;
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;

@Slf4j
public class AuthenticationSuccessHandler implements
    org.springframework.security.web.authentication.AuthenticationSuccessHandler {

  private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

  @Override
  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
      Authentication authentication) throws IOException {
    log.info("SUCESS HANDLER INVOKED");
    String targetUrl = (String) request.getSession().getAttribute(AuthenticationHttpSessionAttributes.TARGET_URL);

    if (targetUrl == null) {
      targetUrl = "/account";
    }

    this.redirectStrategy.sendRedirect(request, response, targetUrl);
    this.clearSessionAuthenticationAttributes(request);
  }

  private void clearSessionAuthenticationAttributes(HttpServletRequest request) {
    request.getSession().removeAttribute(AuthenticationHttpSessionAttributes.TARGET_URL);
  }
}
