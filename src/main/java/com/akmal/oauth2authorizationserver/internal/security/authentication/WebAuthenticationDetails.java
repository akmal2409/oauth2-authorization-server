package com.akmal.oauth2authorizationserver.internal.security.authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class WebAuthenticationDetails {

  private final HttpServletRequest request;
  private final HttpServletResponse response;


  public WebAuthenticationDetails(HttpServletRequest request, HttpServletResponse response) {
    this.request = request;
    this.response = response;
  }

  public HttpServletRequest getRequest() {
    return request;
  }

  public HttpServletResponse getResponse() {
    return response;
  }
}
