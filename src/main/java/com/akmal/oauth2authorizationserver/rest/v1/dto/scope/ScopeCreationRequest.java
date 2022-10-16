package com.akmal.oauth2authorizationserver.rest.v1.dto.scope;

import com.akmal.oauth2authorizationserver.model.client.Scope;
import javax.validation.constraints.NotBlank;

public record ScopeCreationRequest(
    @NotBlank String name,
    @NotBlank String description
) {


  public Scope toScope() {
    return new Scope(null, this.name, false, this.description);
  }
}
