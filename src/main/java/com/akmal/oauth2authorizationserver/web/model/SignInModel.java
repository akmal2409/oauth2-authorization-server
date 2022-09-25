package com.akmal.oauth2authorizationserver.web.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SignInModel {
  private String username;
  private String password;
  private boolean rememberMe;
}
