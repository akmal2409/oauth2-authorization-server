package com.akmal.oauth2authorizationserver.service.v1.auth;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import static org.assertj.core.api.Assertions.*;

import com.akmal.oauth2authorizationserver.exception.InternalServerErrorException;
import com.akmal.oauth2authorizationserver.exception.validation.FailedUserCreationException;
import com.akmal.oauth2authorizationserver.idgen.Generator;
import com.akmal.oauth2authorizationserver.model.Role;
import com.akmal.oauth2authorizationserver.model.user.User;
import com.akmal.oauth2authorizationserver.oauth2.web.model.SignUpModel;
import com.akmal.oauth2authorizationserver.repository.RoleRepository;
import com.akmal.oauth2authorizationserver.repository.UserRepository;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

@ExtendWith(MockitoExtension.class)
class AuthenticationServiceTest {
  @Mock
  UserRepository userRepository;

  @Mock
  PasswordEncoder passwordEncoder;

  @Mock
  RoleRepository roleRepository;

  @Mock
  Generator<String> idGenerator;

  @InjectMocks
  AuthenticationService authenticationService;

  @Captor
  ArgumentCaptor<User> userArgumentCaptor;


  @Test
  @DisplayName("Test createUser should fail and throw exception when email is taken")
  void testCreateUserWhenEmailIsTaken() {
    final var givenEmail = "test@gmail.com";
    final var signUpModel = new SignUpModel("pass", "firstName", "lastName", "lastName", givenEmail);
    when(this.userRepository.hasEmail(anyString())).thenReturn(true);

    assertThatThrownBy(() -> {
      this.authenticationService.createUser(signUpModel);
    }, "Should have thrown FailedUserCreationException because the email is taken")
        .isInstanceOf(FailedUserCreationException.class);

    verify(userRepository, times(1)).hasEmail(anyString());
    verifyNoMoreInteractions(userRepository, passwordEncoder, roleRepository, idGenerator);
  }

  @Test
  @DisplayName("Test createUser should fail and throw exception when default user role is not found")
  void testCreateUserShouldFailWhenDefaultRolesAreNotPresent() {
    final var signUpModel = new SignUpModel("pass", "firstName", "lastName", "lastName", "test");

    when(this.userRepository.hasEmail(anyString())).thenReturn(false);
    when(this.roleRepository.findByName(anyString())).thenReturn(Optional.empty());

    assertThatThrownBy(() -> {
      this.authenticationService.createUser(signUpModel);
    }, "Should have thrown InternalServerErrorException because default role is not available")
        .isInstanceOf(InternalServerErrorException.class);

    verify(this.userRepository, times(1)).hasEmail(anyString());
    verify(this.roleRepository, times(1)).findByName(anyString());
    verifyNoMoreInteractions(this.userRepository, this.roleRepository, this.idGenerator, this.passwordEncoder);
  }

  @Test
  @DisplayName("Test createUser should succeed and persist all properties")
  void testCreateUserShouldSucceedAndSaveAllProperties() {
    final var signUpModel = new SignUpModel("pass", "firstName", "lastName", "lastName", "test@gmail.com");
    final var defaultRole = new Role(1, "ROLE_USER");
    final var expectedId = "id";
    final var expectedHashedPassword = "hashed";

    final var expectedUser = new User(
        expectedId, "firstName lastName", expectedHashedPassword, "firstName", "lastName", "lastName", null, null, null,
        Instant.now(), "test@gmail.com", null, false, List.of(), List.of(defaultRole)
    );

    when(userRepository.hasEmail(anyString())).thenReturn(false);
    when(idGenerator.next()).thenReturn(expectedId);
    when(roleRepository.findByName(anyString())).thenReturn(Optional.of(defaultRole));
    when(passwordEncoder.encode(anyString())).thenReturn(expectedHashedPassword);

    authenticationService.createUser(signUpModel);
    verify(this.userRepository).save(userArgumentCaptor.capture());

    final var actualUser = userArgumentCaptor.getValue();

    assertThat(actualUser)
        .usingRecursiveComparison()
        .ignoringFields("createdAt", "updatedAt")
        .isEqualTo(expectedUser);

    assertThat(actualUser).extracting(User::getCreatedAt).isNotNull();
    assertThat(actualUser).extracting(User::getUpdatedAt).isNull();

    verify(userRepository, times(1)).hasEmail(anyString());
    verify(userRepository, times(1)).save(any(User.class));
    verify(idGenerator, times(1)).next();
    verify(passwordEncoder, times(1)).encode(anyString());
    verify(roleRepository, times(1)).findByName(anyString());
    verifyNoMoreInteractions(userRepository, roleRepository, idGenerator, passwordEncoder);
  }
}
