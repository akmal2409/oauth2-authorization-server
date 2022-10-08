package com.akmal.oauth2authorizationserver.model;

import com.akmal.oauth2authorizationserver.oauth2.model.OAuth2CodeChallengeMethod;
import com.vladmihalcea.hibernate.type.json.JsonType;
import java.time.Instant;
import java.util.List;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.persistence.Transient;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.Type;
import org.hibernate.annotations.TypeDef;
import org.springframework.data.domain.Persistable;

@TypeDef(name = "json", typeClass = JsonType.class)
@Table(name = "Authorization_code_pending_request")
@Entity
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class OAuth2AuthorizationCodePendingRequest implements Persistable<String> {
  @Id
  @Column(name = "code")
  private String code;

  @Column(name = "client_id")
  private String clientId;

  @Column(name = "redirect_uri")
  private String redirectUri;

  @Column(name = "code_challenge")
  private String codeChallenge;

  @Enumerated(EnumType.STRING)
  @Column(name = "code_challenge_method")
  private OAuth2CodeChallengeMethod codeChallengeMethod;

  @Type(type = "json")
  @Column(name = "scopes")
  private List<String> scopes;

  @Column(name = "expires_at")
  private Instant expiresAt;

  @Column(name = "sub")
  private String sub;

  @Transient
  private boolean newEntity;

  @Override
  public String getId() {
    return this.code;
  }

  @Override
  public boolean isNew() {
    return newEntity;
  }
}
