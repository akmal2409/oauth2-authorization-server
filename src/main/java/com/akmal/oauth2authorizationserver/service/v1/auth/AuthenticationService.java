package com.akmal.oauth2authorizationserver.service.v1.auth;

import com.akmal.oauth2authorizationserver.exception.InternalServerErrorException;
import com.akmal.oauth2authorizationserver.exception.validation.FailedUserCreationException;
import com.akmal.oauth2authorizationserver.idgen.Generator;
import com.akmal.oauth2authorizationserver.model.Role.RoleType;
import com.akmal.oauth2authorizationserver.repository.RoleRepository;
import com.akmal.oauth2authorizationserver.repository.UserRepository;
import com.akmal.oauth2authorizationserver.oauth2.web.model.SignUpModel;
import java.time.Instant;
import java.util.List;
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

  private final UserRepository userRepository;

  private final PasswordEncoder passwordEncoder;

  private final RoleRepository roleRepository;

  @Qualifier("idGenerator") private final Generator<String> idGenerator;


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
