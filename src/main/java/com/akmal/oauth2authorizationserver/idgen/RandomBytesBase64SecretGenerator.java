package com.akmal.oauth2authorizationserver.idgen;

import java.util.Base64;
import java.util.concurrent.ThreadLocalRandom;

public class RandomBytesBase64SecretGenerator implements Generator<String> {
  private final int length;
  private final int numberOfBits;

  public RandomBytesBase64SecretGenerator(int length) {
    this.length = length;
    this.numberOfBits = (int) Math.ceil((length * 6)/8.0d);
  }

  /**
   * Creates a random base64 string url safe and without padding.
   *
   * @return url safe, no padding base64.
   */
  @Override
  public String next() {
    final var bytes = new byte[numberOfBits];
    ThreadLocalRandom.current().nextBytes(bytes);

    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }
}
