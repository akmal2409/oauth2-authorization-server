package com.akmal.oauth2authorizationserver.service.v1.auth;

import com.akmal.oauth2authorizationserver.exception.validation.authentication.InvalidAuthenticationRequestException;
import com.akmal.oauth2authorizationserver.idgen.Generator;
import com.akmal.oauth2authorizationserver.model.authentication.AuthenticationProperties;
import com.akmal.oauth2authorizationserver.model.authentication.AuthenticationTransaction;
import com.akmal.oauth2authorizationserver.parser.Parser;
import com.akmal.oauth2authorizationserver.repository.authentication.AuthenticationTransactionRepository;
import com.akmal.oauth2authorizationserver.repository.client.ClientRepository;
import com.akmal.oauth2authorizationserver.validator.Validator;
import java.time.Instant;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
  private final AuthenticationTransactionRepository authTransactionRepository;
  @Qualifier("authenticationPropertiesValidator") private final Validator<AuthenticationProperties> authPropsValidator;
  @Qualifier("authenticationAttributeToPropertiesParser") private final Parser<Map<String, String>, AuthenticationProperties> authAttributeToTransactionParser;
  private final ClientRepository clientRepository;
  @Qualifier("idGenerator") private final Generator<String> idGenerator;
  @Transactional
  public AuthenticationTransaction beginAuthenticationTransaction(Map<String, String> params) {
    final AuthenticationProperties parsedProps = this.authAttributeToTransactionParser.parse(params);
    this.authPropsValidator.validate(parsedProps);

    final var client = this.clientRepository.findById(parsedProps.clientId())
                           .orElseThrow(() -> new InvalidAuthenticationRequestException("Client was not found"));

    if (!client.isWebAuthFlowAllowed()) {
      throw new InvalidAuthenticationRequestException("You are not allowed to use authentication web-flow");
    }

    if (client.getSignInRedirectUris().stream().noneMatch(u -> u.equals(parsedProps.redirectUri()))) {
      throw new InvalidAuthenticationRequestException(String.format("Redirect URI %s is not whitelisted",
          parsedProps.redirectUri()));
    }
    final var transactionId = this.idGenerator.next();

    return this.authTransactionRepository.save(
        parsedProps.toTransaction().withId(transactionId)
            .withTimestamp(Instant.now())
    );
  }
}
