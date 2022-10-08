package com.akmal.oauth2authorizationserver.oauth2.web.model;

import com.akmal.oauth2authorizationserver.model.client.Scope;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class Consent {
  private String targetUrl;
  private String clientId;
  private List<Scope> allowedScopes;
}
