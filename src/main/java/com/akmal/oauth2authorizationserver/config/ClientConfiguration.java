package com.akmal.oauth2authorizationserver.config;

import com.akmal.oauth2authorizationserver.idgen.Generator;
import com.akmal.oauth2authorizationserver.idgen.SecretGenerator;
import com.akmal.oauth2authorizationserver.idgen.ShortenedUUIDGenerator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

@Configuration
public class ClientConfiguration {

  @Bean
  @Primary
  Generator<String> idGenerator() {
    return new ShortenedUUIDGenerator();
  }

  @Bean
  Generator<String> secretGenerator() {
    return null;
  }
}
