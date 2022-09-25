package com.akmal.oauth2authorizationserver.model.authentication;

public enum AuthResponseType {
  CODE, TOKEN, ID_TOKEN;


  public static AuthResponseType from(String name) {
    for (AuthResponseType type: values()) {
      if (type.toString().equalsIgnoreCase(name)) return type;
    }

    return null;
  }
}
