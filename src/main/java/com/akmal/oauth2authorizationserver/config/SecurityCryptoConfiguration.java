package com.akmal.oauth2authorizationserver.config;

import com.akmal.oauth2authorizationserver.idgen.Generator;
import com.akmal.oauth2authorizationserver.idgen.RandomBytesBase64SecretGenerator;
import com.akmal.oauth2authorizationserver.idgen.SecretGenerator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class SecurityCryptoConfiguration {

  @Bean
  PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  Generator<String> secretGenerator() {
    return new RandomBytesBase64SecretGenerator(32);
  }
}
