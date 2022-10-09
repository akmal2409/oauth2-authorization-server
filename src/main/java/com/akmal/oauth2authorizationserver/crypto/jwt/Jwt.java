package com.akmal.oauth2authorizationserver.crypto.jwt;

import com.akmal.oauth2authorizationserver.crypto.jwt.signature.JwtSignatureStrategy;
import com.akmal.oauth2authorizationserver.exception.crypto.JwtCreationException;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

public class Jwt {

  private Algorithm alg;
  private final JwtType typ = JwtType.JWT;
  private List<Claim> claims;
  private String encodedToken;
  private String encodedHeader;
  private String encodedPayload;
  private String encodedSignature;
  private final ObjectMapper objectMapper;

  private Jwt(JwtBuilder builder, Key privateKey)
      throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
    this(builder.alg == null ? Algorithm.RS256 : builder.alg,
        Stream.concat(builder.reservedClaims.stream(), builder.customClaims.stream()).toList(),
        builder.objectMapper);
    this.encodedHeader = this.encodeHeader();
    this.encodedPayload = this.encodePayload();
    this.encodedSignature = Base64.getUrlEncoder().withoutPadding().encodeToString(this.sign(privateKey));
    this.encodedToken = encodedHeader
                            .concat(".")
                            .concat(encodedPayload)
                            .concat(".")
                            .concat(encodedSignature);
  }

  private Jwt(Algorithm alg, List<Claim> claims, ObjectMapper mapper) {
    this.alg = alg;
    this.claims = claims;
    this.objectMapper = mapper;
  }

  private String encodeHeader() {
    Map<String, Object> header = new LinkedHashMap<>();
    header.put(JwtAttributeNames.ALG, this.alg);
    header.put(JwtAttributeNames.TYP, this.typ);

    try {
      return Base64.getUrlEncoder().withoutPadding().encodeToString(
          this.objectMapper.writeValueAsBytes(header)
      );
    } catch (JsonProcessingException e) {
      throw new JwtCreationException("Error while writing header", e);
    }
  }

  private String encodePayload() {
    Map<String, Object> payload = new LinkedHashMap<>();

    for (Claim claim : this.claims) {
      payload.put(claim.name(), claim.value());
    }
    try {
      return Base64.getUrlEncoder().withoutPadding().encodeToString(
          this.objectMapper.writeValueAsBytes(payload)
      );
    } catch (JsonProcessingException e) {
      throw new JwtCreationException("Error while writing payload", e);
    }
  }

  private byte[] sign(Key privateKey)
      throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
    return JwtSignatureStrategy.withKey(privateKey, this.alg)
               .sign(this.encodedHeader, this.encodedPayload);
  }

  public static JwtBuilder withMapper(ObjectMapper objectMapper) {
    return new JwtBuilder(objectMapper);
  }

  public static class JwtBuilder {

    private Algorithm alg;
    private final List<Claim> reservedClaims = new LinkedList<>();
    private final List<Claim> customClaims = new LinkedList<>();
    private final ObjectMapper objectMapper;

    public JwtBuilder(ObjectMapper objectMapper) {
      this.objectMapper = objectMapper;
    }

    public JwtBuilder alg(Algorithm alg) {
      this.alg = alg;
      return this;
    }


    public JwtBuilder sub(String sub) {
      this.reservedClaims.add(new Claim(JwtAttributeNames.SUB, sub));
      return this;
    }

    public JwtBuilder reservedClaim(Claim claim) {
      this.reservedClaims.add(claim);
      return this;
    }

    public JwtBuilder claim(Claim claim) {
      this.customClaims.add(claim);
      return this;
    }

    public Jwt sign(Key key)
        throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
      return new Jwt(this, key);
    }
  }

  public Algorithm getAlg() {
    return alg;
  }

  public JwtType getTyp() {
    return typ;
  }

  public List<Claim> getClaims() {
    return claims;
  }

  public String getEncodedToken() {
    return encodedToken;
  }

  public String getEncodedHeader() {
    return encodedHeader;
  }

  public String getEncodedPayload() {
    return encodedPayload;
  }

  public String getEncodedSignature() {
    return encodedSignature;
  }

  public ObjectMapper getObjectMapper() {
    return objectMapper;
  }
}
