package com.akmal.oauth2authorizationserver.oauth2.token.issuance;

public enum TokenType {
  BEARER("Bearer");

  private String name;

  TokenType(String name) {
    this.name = name;
  }

  public String getName() {
    return name;
  }
}
