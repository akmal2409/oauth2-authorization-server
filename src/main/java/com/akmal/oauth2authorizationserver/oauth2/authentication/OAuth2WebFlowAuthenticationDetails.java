package com.akmal.oauth2authorizationserver.oauth2.authentication;

import javax.servlet.http.HttpServletRequest;

public record OAuth2WebFlowAuthenticationDetails(HttpServletRequest request) {

}
