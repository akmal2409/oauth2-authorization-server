package com.akmal.oauth2authorizationserver.oauth2.authconverter;

import javax.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;

public interface AuthenticationHttpRequestConverter {

  Authentication convert(HttpServletRequest request);
}
