package com.akmal.oauth2authorizationserver.idgen;

import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Implementation of the {@link Generator} interface that generates
 * shorter, more human readable UUID's by stripping the dashes and lowercasing
 * the characters.
 */
public class ShortenedUUIDGenerator implements Generator<String> {
  private static final Pattern DASH_ID_PATTERN = Pattern.compile("-");

  /**
   * Creates 128 bit UUID provided by {@link UUID}, then lowercases the output
   * and strips the dashes using {@link ShortenedUUIDGenerator#DASH_ID_PATTERN}.
   *
   * @return lowercased UUID without dashes (32 characters).
   */
  public String next() {
    final var uuid = UUID.randomUUID().toString()
               .toLowerCase();

    return DASH_ID_PATTERN.matcher(uuid).replaceAll("");
  }
}
