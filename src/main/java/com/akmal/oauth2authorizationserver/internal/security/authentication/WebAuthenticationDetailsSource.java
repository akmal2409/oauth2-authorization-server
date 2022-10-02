package com.akmal.oauth2authorizationserver.internal.security.authentication;

import com.akmal.oauth2authorizationserver.oauth2.authprovider.Tuple;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationDetailsSource;

public class WebAuthenticationDetailsSource implements AuthenticationDetailsSource<Tuple<HttpServletRequest, HttpServletResponse>, WebAuthenticationDetails> {

  @Override
  public WebAuthenticationDetails buildDetails(
      Tuple<HttpServletRequest, HttpServletResponse> context) {
    return new WebAuthenticationDetails(context.getT1(), context.getT2());
  }
}
