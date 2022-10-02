package com.akmal.oauth2authorizationserver.service.v1.auth;

import com.akmal.oauth2authorizationserver.exception.auth.AuthenticationException;
import com.akmal.oauth2authorizationserver.idgen.Generator;
import com.akmal.oauth2authorizationserver.internal.security.authentication.SessionCookieAuthentication;
import com.akmal.oauth2authorizationserver.internal.security.authentication.WebAuthenticationDetails;
import com.akmal.oauth2authorizationserver.model.Role;
import com.akmal.oauth2authorizationserver.oauth2.AuthenticationHttpSessionAttributes;
import com.akmal.oauth2authorizationserver.oauth2.authentication.OAuth2WebFlowAuthenticationDetails;
import com.akmal.oauth2authorizationserver.repository.UserRepository;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.apache.catalina.User;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@RequiredArgsConstructor
public class UserCredentialsAuthenticationProvider implements AuthenticationProvider {
  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;
  private final Generator<String> keyGenerator;

  @Transactional(readOnly = true)
  @Override
  public Authentication authenticate(Authentication authentication)  {

    final var user = this.userRepository.findByEmail(authentication.getName())
                         .orElseThrow(() -> new BadCredentialsException("Invalid credentials"));

    if (!user.isEmailVerified()) throw new AuthenticationException("Please verify your email");

    if (!this.passwordEncoder.matches(authentication.getCredentials().toString(), user.getPassword())) {
      throw new BadCredentialsException("Invalid credentials");
    }

    final WebAuthenticationDetails authenticationDetails = (WebAuthenticationDetails) authentication.getDetails();
    if (authenticationDetails == null) return null;

    HttpServletRequest request = authenticationDetails.getRequest();
    HttpServletResponse response = authenticationDetails.getResponse();
    if (request == null || response == null) return null;

    final var sessionId = this.keyGenerator.next();
    final var sessionCookie = new Cookie(AuthenticationHttpSessionAttributes.SSO_SESSION_ID, sessionId);

    sessionCookie.setMaxAge(3600*5); // 5hours
    response.addCookie(sessionCookie);

    return  new SessionCookieAuthentication(user.getRoles().stream().map(Role::getName).map(SimpleGrantedAuthority::new).toList(),
        sessionId,
        user.getSub(),
        true
        );
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
  }
}
