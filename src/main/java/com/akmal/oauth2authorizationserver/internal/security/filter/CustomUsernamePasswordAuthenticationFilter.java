package com.akmal.oauth2authorizationserver.internal.security.filter;

import com.akmal.oauth2authorizationserver.oauth2.authprovider.Tuple;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Slf4j
public class CustomUsernamePasswordAuthenticationFilter extends
    UsernamePasswordAuthenticationFilter {

  /**
   * The URL where the POST request with credentials must be submitted.
   */
  private static final String DEFAULT_PROCESS_URL = "/authenticate-process";
  private static final String DEFAULT_USERNAME_PARAMETER_NAME = "email";
  private static final String DEFAULT_PASSWORD_PARAMETER_NAME = "password";

  private final String usernameParameterName;
  private final String passwordParameterName;
  private final AuthenticationDetailsSource<Tuple<HttpServletRequest, HttpServletResponse>, ?> authenticationDetailsSource;

  public CustomUsernamePasswordAuthenticationFilter(AuthenticationManager authenticationManager,
      AuthenticationDetailsSource<Tuple<HttpServletRequest, HttpServletResponse>, ?> authenticationDetailsSource) {
    super(authenticationManager);
    this.authenticationDetailsSource = authenticationDetailsSource;
    this.usernameParameterName = DEFAULT_USERNAME_PARAMETER_NAME;
    this.passwordParameterName = DEFAULT_PASSWORD_PARAMETER_NAME;
    this.setFilterProcessesUrl(DEFAULT_PROCESS_URL);
  }


  @Override
  public Authentication attemptAuthentication(HttpServletRequest request,
      HttpServletResponse response) throws AuthenticationException {
    if (!HttpMethod.POST.name().equals(request.getMethod())) {
      throw new AuthenticationServiceException("HTTP method is not supported: " + request.getMethod());
    }

    var username = request.getParameter(this.usernameParameterName) != null ? request.getParameter(this.usernameParameterName) : "";
    var password = request.getParameter(this.passwordParameterName) != null ? request.getParameter(this.passwordParameterName) : "";


    final var authentication =  UsernamePasswordAuthenticationToken.unauthenticated(username, password);

    authentication.setDetails(this.authenticationDetailsSource.buildDetails(new Tuple<>(request, response)));

    return super.getAuthenticationManager().authenticate(authentication);
  }
}
