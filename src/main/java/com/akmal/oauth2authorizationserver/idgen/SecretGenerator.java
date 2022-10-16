package com.akmal.oauth2authorizationserver.idgen;

import com.akmal.oauth2authorizationserver.shared.utils.ByteUtils;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

@Deprecated
public class SecretGenerator implements Generator<String> {

  private static final String LOWERCASE_LETTERS = "abcdefghijklmnopqrstuvwxyz";
  private static final String UPPERCASE_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  private static final String SYMBOLS = ",.+=-&#!~?";
  private static final String NUMBERS = "123456789";
  public static final int DEFAULT_LENGTH = 32;
  private final SecureRandom secureRandom;
  private final List<String> characterSets;

  private final int length;

  private SecretGenerator(Builder builder) {
    byte[] seedBytes;
    if (builder.seed != null) {
      seedBytes = ByteUtils.longToByteArray(builder.seed);
    } else {
      seedBytes = SecureRandom.getSeed(8);
    }
    this.secureRandom = new SecureRandom(seedBytes);
    this.characterSets = new ArrayList<>();


    if (builder.useNumbers) {
      this.characterSets.add(NUMBERS);
    }

    if (builder.useSymbols) {
      this.characterSets.add(SYMBOLS);
    }

    if (builder.useLowerCaseLetters) {
      this.characterSets.add(LOWERCASE_LETTERS);
    }
    if (builder.useUpperCaseLetters) {
      this.characterSets.add(UPPERCASE_LETTERS);
    }

    if (builder.length != null) {
      this.length = builder.length;
    } else {
      this.length = DEFAULT_LENGTH;
    }
  }

  @Override
  public String next() {
    final StringBuilder sb = new StringBuilder(this.length);

    for (int i = 0; i < this.length; i++) {
      final int characterSetIndex = this.secureRandom.nextInt(this.characterSets.size());
      final String characterSet = this.characterSets.get(characterSetIndex);

      final int characterIndex = this.secureRandom.nextInt(characterSet.length());
      sb.append(characterSet.charAt(characterIndex));
    }

    return sb.toString();
  }

  public static class Builder {
    private boolean useLowerCaseLetters = true;
    private boolean useUpperCaseLetters = true;
    private boolean useSymbols = true;
    private boolean useNumbers = true;
    private Integer length;
    private Long seed;

    public Builder useLowerCaseLetters(boolean value) {
      this.useLowerCaseLetters = value;
      return this;
    }

    public Builder useUpperCaseLetters(boolean value) {
      this.useUpperCaseLetters = value;
      return this;
    }

    public Builder useSymbols(boolean value) {
      this.useSymbols = value;
      return this;
    }

    public Builder useNumbers(boolean value) {
      this.useNumbers = value;
      return this;
    }

    public Builder withSeed(long seed) {
      this.seed = seed;
      return this;
    }

    public Builder withLength(int length) {
      this.length = length;
      return this;
    }

    public SecretGenerator build() {
      return new SecretGenerator(this);
    }
  }
}
