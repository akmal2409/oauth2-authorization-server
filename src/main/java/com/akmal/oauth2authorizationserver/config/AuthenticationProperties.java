package com.akmal.oauth2authorizationserver.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@ConfigurationProperties(prefix = "project.authentication")
public class AuthenticationProperties {
  private String loginUrl;
  private String loginProcessUrl;
  private String usernameParameterName;
  private String passwordParameterName;
}
