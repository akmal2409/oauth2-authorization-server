package com.akmal.oauth2authorizationserver.config;

import java.nio.file.Path;
import java.nio.file.Paths;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Represents a set of internal configuration properties,
 * such as token validity, default URLs of consent pages etc.
 */
@Configuration
@ConfigurationProperties(prefix = "oauth2.internal")
@Getter
@Setter
public class InternalOAuth2ConfigurationProperties {

  private Path configDir  = Paths.get(System.getProperty("user.home"), ".authorization_server");
  private String keysDirectoryName = "keys";
  private String privateKeyAlias = "token.signer.private";
  private String certificateAlias = "token.signer.certificate";
  private String keyStoreName = "keystore.p12";
  private String keyStoreType = "PKCS12";
  private String keyStorePassword = "password";
  private String signatureAlg = "SHA256withRSA";
  private String keyAlg = "RSA";
  private int keyLength = 2048;
  private String issuerUrl = "http://localhost:8080";
  private long tokenValidityMs = 15 * 60 * 1000; // 15min

}
