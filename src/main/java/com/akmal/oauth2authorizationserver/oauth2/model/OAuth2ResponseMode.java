package com.akmal.oauth2authorizationserver.oauth2.model;

public enum OAuth2ResponseMode {
  FRAGMENT, FORM_POST, QUERY;

  public static OAuth2ResponseMode from(String name) {
    for (OAuth2ResponseMode mode: values()) {
      if (mode.toString().equalsIgnoreCase(name)) return mode;
    }

    return null;
  }
}
