package com.akmal.oauth2authorizationserver.crypto.jwt.signature;

import com.akmal.oauth2authorizationserver.crypto.jwt.Algorithm;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

public interface JwtSignatureStrategy {

  byte[] sign(String base64UrlEncodeHeader, String base64UrlEncodePayload)
      throws NoSuchAlgorithmException, InvalidKeyException, SignatureException;

  static JwtSignatureStrategy withKey(Key privateKey, Algorithm algorithm) {
    return switch (algorithm) {
      case RS256 -> new RS256JwtSignatureStrategy(privateKey);
      default -> null;
    };
  }
}
