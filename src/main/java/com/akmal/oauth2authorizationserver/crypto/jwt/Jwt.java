package com.akmal.oauth2authorizationserver.crypto.jwt;

import com.akmal.oauth2authorizationserver.crypto.jwt.signature.JwtSignatureStrategy;
import com.akmal.oauth2authorizationserver.exception.crypto.JwtCreationException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.time.Instant;
import java.util.Base64;
import java.util.Collection;
import java.util.HashMap;
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

  private Instant expiresAt;
  private final ObjectMapper objectMapper;

  private Map<String, Object> properties;

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
    this.properties = new HashMap<>();
    this.expiresAt = builder.expiresAt;

    for (Claim claim: this.claims) {
      this.properties.put(claim.name(), claim.value());
    }
  }

  private Jwt(Algorithm alg, List<Claim> claims, ObjectMapper mapper) {
    this.alg = alg;
    this.claims = claims;
    this.objectMapper = mapper;
    this.properties = new HashMap<>();
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
    private Instant expiresAt;

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

    public JwtBuilder aud(String aud) {
      this.reservedClaims.add(new Claim(JwtAttributeNames.AUD, aud));
      return this;
    }

    public JwtBuilder iss(String iss) {
      this.reservedClaims.add(new Claim(JwtAttributeNames.ISS, iss));
      return this;
    }

    public JwtBuilder exp(long exp) {
      this.reservedClaims.add(new Claim(JwtAttributeNames.EXP, exp));
      this.expiresAt = Instant.ofEpochMilli(exp);
      return this;
    }

    public JwtBuilder nbf(long nbf) {
      this.reservedClaims.add(new Claim(JwtAttributeNames.NBF, nbf));
      return this;
    }

    public JwtBuilder iat(long iat) {
      this.reservedClaims.add(new Claim(JwtAttributeNames.IAT, iat));
      return this;
    }

    public JwtBuilder jti(String jti) {
      this.reservedClaims.add(new Claim(JwtAttributeNames.JTI, jti));
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

    public JwtBuilder claims(Collection<Claim> claims) {
      this.customClaims.addAll(claims);
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

  public Instant getExpiresAt() {
    return expiresAt;
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

  public Object claim(String claim) {
    return this.properties.get(claim);
  }

  public String claimAsString(String claim) {
    return (String) this.claim(claim);
  }

  public Integer claimAsInteger(String claim) {
    return (Integer) this.claim(claim);
  }

  public Double claimAsDouble(String claim) {
    return (Double) this.claim(claim);
  }

  public BigInteger claimAsBigInteger(String claim) {
    return (BigInteger) this.claim(claim);
  }

  public Boolean claimAsBoolean(String claim) {
    return (Boolean) this.claim(claim);
  }

  public Float claimAsFloat(String claim) {
    return (Float) this.claim(claim);
  }

  public Long claimAsLong(String claim) {
    return (Long) this.claim(claim);
  }
}
