package com.akmal.oauth2authorizationserver.oauth2.token.issuance;

import com.akmal.oauth2authorizationserver.config.InternalOAuth2ConfigurationProperties;
import com.akmal.oauth2authorizationserver.crypto.RsaKeyService;
import com.akmal.oauth2authorizationserver.crypto.jwt.Algorithm;
import com.akmal.oauth2authorizationserver.crypto.jwt.Claim;
import com.akmal.oauth2authorizationserver.crypto.jwt.Jwt;
import com.akmal.oauth2authorizationserver.crypto.jwt.Jwt.JwtBuilder;
import com.akmal.oauth2authorizationserver.crypto.jwt.JwtAttributeNames;
import com.akmal.oauth2authorizationserver.exception.token.TokenIssuanceFailedException;
import com.akmal.oauth2authorizationserver.model.client.GrantType;
import com.akmal.oauth2authorizationserver.oauth2.config.OidcScopes;
import com.akmal.oauth2authorizationserver.repository.UserRepository;
import com.akmal.oauth2authorizationserver.shared.persistence.TransactionPropagator;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The service class encapsulates the logic of token issuance, that includes deciding whether to
 * issue an ID token based on the grant, whether to include refresh_token or what claims to returned
 * based on the default OIDC scopes.
 */
@Service
public class TokenIssueService {

  private final RsaKeyService rsaKeyService;
  private final ObjectMapper objectMapper;
  private final InternalOAuth2ConfigurationProperties internalOauthConfigProps;
  private final TransactionPropagator transactionPropagator;
  private final UserRepository userRepository;

  public TokenIssueService(RsaKeyService rsaKeyService, ObjectMapper objectMapper,
      InternalOAuth2ConfigurationProperties internalOauthConfigProps,
      TransactionPropagator transactionPropagator, UserRepository userRepository) {
    this.rsaKeyService = rsaKeyService;
    this.objectMapper = objectMapper;
    this.internalOauthConfigProps = internalOauthConfigProps;
    this.transactionPropagator = transactionPropagator;
    this.userRepository = userRepository;
  }

  /**
   * Issues the token response as json object (in this case a map) which may contain refresh_token
   * if the scope offline_access is present, it will always include an ID token as well as an access
   * token.
   *
   * @param properties set of properties that identify the client and the subject with granted
   *                   scopes.
   * @return json representation of the set of tokens
   */
  @Transactional
  public Map<String, Object> issueTokenSet(OAuth2TokenIssueProperties properties) {

    final var tokenSet = new HashMap<String, Object>();

    final var accessTokenJwt =
        this.transactionPropagator.withinCurrent(() -> {
          try {
            return this.issueAccessToken(properties.sub(), properties.clientId(),
                properties.scopes());
          } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            throw new TokenIssuanceFailedException("Failed to generate access token", e);
          }
        });
    tokenSet.put(OAuth2TokenAttributeNames.ACCESS_TOKEN, accessTokenJwt.getEncodedToken());
    Set<String> scopeSet = new HashSet<>(properties.scopes());

    // if the client credentials grant is used, then we should not include any user related scopes, neither an ID token
    // client_credentials grant is aimed only at machine-to-machine communication.
    if (scopeSet.contains(OidcScopes.OPENID) && !GrantType.CLIENT_CREDENTIALS.equals(
        properties.grantType())) {
      final var idTokenJwt = this.transactionPropagator.withinCurrent(() -> {
        try {
          return this.issueIdToken(
              properties.sub(), properties.clientId(), scopeSet);
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
          throw new TokenIssuanceFailedException("Failed to generate id token", e);
        }
      });
      tokenSet.put(OAuth2TokenAttributeNames.ID_TOKEN, idTokenJwt.getEncodedToken());
    }

    if (scopeSet.contains(OidcScopes.OFFLINE_ACCESS)) {
      // TODO: implement refresh tokens.
    }

    return tokenSet;
  }

  /**
   * Method issues the ID token conforming to the OpenID connect specification. It includes user
   * related claims based on the provided scopes.
   * <ol>
   *   <li>
   *     <span>If the email scope is present</span>
   *     <ul>
   *       <li>Includes email address of the user</li>
   *     </ul>
   *   </li>
   *
   *    <li>
   *     <span>If the phone scope is present</span>
   *     <ul>
   *       <li>Includes phone number of the user</li>
   *     </ul>
   *   </li>
   *
   *    <li>
   *     <span>If the profile scope is present</span>
   *     <ul>
   *       <li>Includes name of the user</li>
   *       <li>Includes middle name of the user</li>
   *       <li>Includes last name of the user</li>
   *       <li>Includes locale of the user</li>
   *       <li>Includes zone_info of the user</li>
   *     </ul>
   *   </li>
   *
   *    <li>
   *     <span>If the openid scope is present</span>
   *     <ul>
   *       <li>Includes user_id</li>
   *       <li>Includes flag email_verified</li>
   *     </ul>
   *   </li>
   * </ol>
   *
   * @param sub    id of the user
   * @param scopes list of scopes that should be included.
   * @return ID token as JWT.
   */
  private Jwt issueIdToken(String sub, String aud, Set<String> scopes)
      throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
    final var user = this.userRepository.findById(sub)
                         .orElseThrow(
                             () -> new TokenIssuanceFailedException("Subject was not found"));

    final var userClaims = user.extractPropertiesBasedOnScopes(scopes)
                               .entrySet().stream().map(e -> new Claim(e.getKey(), e.getValue()))
                               .toList();

    return this.baseJwtConfiguration(sub, aud)
               .claims(userClaims)
               .sign(this.rsaKeyService.getKeyPair().getPrivate());
  }

  /**
   * Method issues access token with minimal amount of properties. It assumes that the OPENID scope
   * is always present and therefore adds the subject.
   * <ul>
   *   <li>The method includes aud claim as the client_id by default.</li>
   *   <li>The token expiration time may be configured in the {@link InternalOAuth2ConfigurationProperties#getTokenValidityMs()}.</li>
   *   <li>Each token is assigned a UUID</li>
   *   <li>Default signature algorithm is {@link Algorithm#RS256}. Meaning it employs RSA private key and a SHA256 hash of the output</li>
   *   <li>Includes iat (issued at time) claim</li>
   * </ul>
   *
   * @param sub    user id
   * @param aud    audience intended
   * @param scopes list of scopes
   * @return
   * @throws NoSuchAlgorithmException
   * @throws SignatureException
   * @throws InvalidKeyException
   */
  private Jwt issueAccessToken(String sub, String aud, List<String> scopes)
      throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
    return this.baseJwtConfiguration(sub, aud)
               .reservedClaim(new Claim(JwtAttributeNames.SCOPE, scopes))
               .sign(this.rsaKeyService.getKeyPair().getPrivate());
  }

  /**
   * Creates a base configuration for the JWT token that includes all the required claims.
   *
   * @param sub user id
   * @param aud audience intended
   * @return jwt builder.
   */
  private JwtBuilder baseJwtConfiguration(String sub, String aud) {
    return Jwt.withMapper(this.objectMapper)
               .alg(Algorithm.RS256)
               .iss(internalOauthConfigProps.getIssuerUrl())
               .sub(sub) // always included because openid scope is always required
               .aud(aud)
               .iat(Instant.now().toEpochMilli())
               .exp(Instant.now()
                        .plus(Duration.ofMillis(internalOauthConfigProps.getTokenValidityMs()))
                        .toEpochMilli())
               .jti(UUID.randomUUID().toString());
  }
}
