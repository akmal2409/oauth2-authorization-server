package com.akmal.oauth2authorizationserver.service.v1.auth;

import com.akmal.oauth2authorizationserver.exception.InternalServerErrorException;
import com.akmal.oauth2authorizationserver.exception.validation.FailedUserCreationException;
import com.akmal.oauth2authorizationserver.exception.validation.authentication.InvalidAuthenticationRequestException;
import com.akmal.oauth2authorizationserver.idgen.Generator;
import com.akmal.oauth2authorizationserver.model.Role.RoleType;
import com.akmal.oauth2authorizationserver.model.authentication.AuthenticationProperties;
import com.akmal.oauth2authorizationserver.model.authentication.AuthenticationTransaction;
import com.akmal.oauth2authorizationserver.parser.Parser;
import com.akmal.oauth2authorizationserver.repository.RoleRepository;
import com.akmal.oauth2authorizationserver.repository.UserRepository;
import com.akmal.oauth2authorizationserver.repository.authentication.AuthenticationTransactionRepository;
import com.akmal.oauth2authorizationserver.repository.client.ClientRepository;
import com.akmal.oauth2authorizationserver.validator.Validator;
import com.akmal.oauth2authorizationserver.web.model.SignUpModel;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationService {
  private final AuthenticationTransactionRepository authTransactionRepository;
  @Qualifier("authenticationPropertiesValidator") private final Validator<AuthenticationProperties> authPropsValidator;
  @Qualifier("authenticationAttributeToPropertiesParser") private final Parser<Map<String, String>, AuthenticationProperties> authAttributeToTransactionParser;
  private final ClientRepository clientRepository;

  private final UserRepository userRepository;

  private final PasswordEncoder passwordEncoder;

  private final RoleRepository roleRepository;

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

  @Transactional
  public void createUser(SignUpModel signUpModel) {
    final var exists = this.userRepository.hasEmail(signUpModel.getEmail());

    if (Boolean.TRUE.equals(exists)) throw new FailedUserCreationException("Email is taken");

    final var userRole = this.roleRepository.findByName(RoleType.ROLE_USER.type)
                             .orElseThrow(() -> {
                               log.error("type=INTERNAL_FAILURE;component=AuthenticationService.java;reason=ROLE_USER not found");
                               return new InternalServerErrorException("Role could not be assigned");
                             });

    final var mappedUser = signUpModel.toUser()
                               .withSub(this.idGenerator.next())
                               .withCreatedAt(Instant.now())
                               .withPassword(this.passwordEncoder.encode(signUpModel.getPassword()))
                               .withEmailVerified(false)
                               .withRoles(List.of(userRole));

    this.userRepository.save(mappedUser);
    // TODO: send verification email
  }
}
