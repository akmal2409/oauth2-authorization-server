package com.akmal.oauth2authorizationserver.crypto.jwt;

public class JwtAttributeNames {

  public static final String ALG = "alg";
  public static final String TYP = "typ";
  public static final String RSA_256 = "RSA256";

  /**
   * Reserved claim containing subject of the token
   */
  public static final String SUB = "sub";

  public static final String ISS = "iss";
  public static final String AUD = "aud";
  public static final String EXP = "exp";
  public static final String NBF = "nbf";
  public static final String IAT = "iat";
  public static final String JTI = "jti";
  public static final String SCOPE = "scope";
}
