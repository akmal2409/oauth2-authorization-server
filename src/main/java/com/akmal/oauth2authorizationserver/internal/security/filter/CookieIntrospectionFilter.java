package com.akmal.oauth2authorizationserver.internal.security.filter;

import com.akmal.oauth2authorizationserver.internal.security.authentication.SessionCookieAuthentication;
import com.akmal.oauth2authorizationserver.internal.security.authentication.WebAuthenticationDetailsSource;
import com.akmal.oauth2authorizationserver.oauth2.AuthenticationHttpSessionAttributes;
import com.akmal.oauth2authorizationserver.oauth2.authprovider.Tuple;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.constraints.NotNull;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.filter.OncePerRequestFilter;

public class CookieIntrospectionFilter extends OncePerRequestFilter {

  private final AuthenticationManager authenticationManager;
  private final WebAuthenticationDetailsSource webAuthenticationDetailsSource;

  public CookieIntrospectionFilter(AuthenticationManager authenticationManager,
      WebAuthenticationDetailsSource webAuthenticationDetailsSource) {
    this.authenticationManager = authenticationManager;
    this.webAuthenticationDetailsSource = webAuthenticationDetailsSource;
  }

  @Transactional(propagation = Propagation.REQUIRES_NEW)
  @Override
  protected void doFilterInternal(HttpServletRequest request,
      HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {
    final var cookie = this.sessionCookieFromRequest(request);

    if (cookie == null) {
      filterChain.doFilter(request, response);
      return;
    }

    final var authentication = this.authenticationManager.authenticate(new SessionCookieAuthentication(List.of(), cookie.getValue(), null, false,
        this.webAuthenticationDetailsSource.buildDetails(new Tuple<>(request, response))));

    if (authentication != null) {
      SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    filterChain.doFilter(request, response);
  }

  private Cookie sessionCookieFromRequest(@NotNull HttpServletRequest request) {
    final var cookies = request.getCookies();
    if (cookies == null) return null;

    return Arrays.stream(cookies)
               .filter(c -> AuthenticationHttpSessionAttributes.SSO_SESSION_ID.equals(c.getName()))
               .findFirst()
               .orElse(null);
  }
}
