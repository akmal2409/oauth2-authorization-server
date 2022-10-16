package com.akmal.oauth2authorizationserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
@EnableAsync
public class Oauth2AuthorizationServerApplication {

  public static void main(String[] args) {
    SpringApplication.run(Oauth2AuthorizationServerApplication.class, args);
  }

}
