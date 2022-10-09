package com.akmal.oauth2authorizationserver.crypto.jwt.signature;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;

class RS256JwtSignatureStrategy implements JwtSignatureStrategy {
  private final Key key;
  RS256JwtSignatureStrategy(Key privateKey) {
    this.key = privateKey;
  }

  @Override
  public byte[] sign(String base64UrlEncodeHeader, String base64UrlEncodePayload)
      throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    final var requiresSignature = base64UrlEncodeHeader.concat(".").concat(base64UrlEncodePayload);
    final var signature = Signature.getInstance("SHA256withRSA");

    signature.initSign((PrivateKey) key);

    signature.update(requiresSignature.getBytes(StandardCharsets.UTF_8));

    return signature.sign();
  }
}
