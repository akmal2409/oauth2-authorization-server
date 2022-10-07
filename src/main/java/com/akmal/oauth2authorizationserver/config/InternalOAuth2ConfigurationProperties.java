package com.akmal.oauth2authorizationserver.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Represents a set of internal configuration properties,
 * such as token validity, default URLs of consent pages etc.
 */
@Configuration
@ConfigurationProperties(prefix = "oauth2.internal")
public class InternalOAuth2ConfigurationProperties {

}
