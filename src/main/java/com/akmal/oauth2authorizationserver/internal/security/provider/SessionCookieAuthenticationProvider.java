package com.akmal.oauth2authorizationserver.internal.security.provider;

import com.akmal.oauth2authorizationserver.internal.security.authentication.SessionCookieAuthentication;
import com.akmal.oauth2authorizationserver.internal.security.authentication.WebAuthenticationDetails;
import com.akmal.oauth2authorizationserver.model.Role;
import com.akmal.oauth2authorizationserver.model.Session;
import com.akmal.oauth2authorizationserver.oauth2.AuthenticationHttpSessionAttributes;
import com.akmal.oauth2authorizationserver.repository.SessionRepository;
import com.akmal.oauth2authorizationserver.shared.persistence.TransactionPropagator;
import javax.servlet.http.Cookie;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.transaction.annotation.Transactional;

public class SessionCookieAuthenticationProvider implements AuthenticationProvider {
  private final SessionRepository sessionRepository;
  private final TransactionPropagator transactionPropagator;

  public SessionCookieAuthenticationProvider(SessionRepository sessionRepository,
      TransactionPropagator transactionPropagator) {
    this.sessionRepository = sessionRepository;
    this.transactionPropagator = transactionPropagator;
  }

  @Transactional
  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    final var session = this.transactionPropagator.withinCurrent(() -> this.getSession(
        (String) authentication.getCredentials()));
    final WebAuthenticationDetails authenticationDetails = (WebAuthenticationDetails) authentication.getDetails();
    if (session == null) {
      final var expiredCookie = new Cookie(AuthenticationHttpSessionAttributes.SSO_SESSION_ID,
          (String) authentication.getCredentials());
      expiredCookie.setMaxAge(0); // expire the cookie
      expiredCookie.setPath("/");
      authenticationDetails.getResponse().addCookie(expiredCookie);
      return null;
    }

    final var roles = session.getUser().getRoles().stream().map(Role::getName).map(
        SimpleGrantedAuthority::new).toList();

    return new SessionCookieAuthentication(roles, session.getId(),
        session.getUser().getSub(), true);
  }

  private Session getSession(String sessionId) {
    final var sessionOptional = this.sessionRepository.findByIdWithUser(sessionId);

    if (sessionOptional.isEmpty()) return null;

    if (sessionOptional.get().isExpired()) return null;

    return sessionOptional.get();
  }


  @Override
  public boolean supports(Class<?> authentication) {
    return SessionCookieAuthentication.class.isAssignableFrom(authentication);
  }
}
