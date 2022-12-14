package com.akmal.oauth2authorizationserver.oauth2.web.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SignInModel {
  private String email;
  private String password;
  private boolean rememberMe;
}
