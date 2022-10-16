package com.akmal.oauth2authorizationserver.service.v1;

import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;

import com.akmal.oauth2authorizationserver.exception.validation.InvalidScopeConfigurationException;
import com.akmal.oauth2authorizationserver.oauth2.config.OidcScopes;
import com.akmal.oauth2authorizationserver.repository.ScopeRepository;
import com.akmal.oauth2authorizationserver.rest.v1.dto.scope.ScopeCreationRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class ScopeServiceTest {

  @Mock
  ScopeRepository scopeRepository;

  @InjectMocks
  ScopeService scopeService;

  @Test
  @DisplayName("saveCustomScope() should throw exception if the scope name is one of the reserved ones")
  void testSaveCustomScopeShouldFailWhenNameReserved() {
    for (String oidcScope: OidcScopes.OIDC_SCOPE_SET) {
      assertThatThrownBy(() -> {
        this.scopeService.saveCustomScope(new ScopeCreationRequest(oidcScope, "DESC"));
      }, "Should have thrown exception because the scope name is reserved " + oidcScope).isInstanceOf(
          InvalidScopeConfigurationException.class);
    }
  }
}
