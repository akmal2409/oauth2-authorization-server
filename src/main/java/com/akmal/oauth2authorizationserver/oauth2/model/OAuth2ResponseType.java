package com.akmal.oauth2authorizationserver.oauth2.model;

public enum OAuth2ResponseType {
  CODE, TOKEN, ID_TOKEN;


  public static OAuth2ResponseType from(String name) {
    for (OAuth2ResponseType type: values()) {
      if (type.toString().equalsIgnoreCase(name)) return type;
    }

    return null;
  }
}
