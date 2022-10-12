package com.akmal.oauth2authorizationserver.model;

import com.akmal.oauth2authorizationserver.model.client.Client;
import com.akmal.oauth2authorizationserver.model.user.User;
import com.vladmihalcea.hibernate.type.json.JsonType;
import java.time.Instant;
import java.util.List;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.Type;
import org.hibernate.annotations.TypeDef;

@Entity
@Table(name = "Refresh_tokens")
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@TypeDef(name = "json", typeClass = JsonType.class)
public class RefreshToken {

  @Id
  @Column(name = "token")
  private String token;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "sub", referencedColumnName = "sub")
  private User user;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "client_id", referencedColumnName = "client_id")
  private Client client;

  @Column(name = "expires_at")
  private Instant expiresAt;

  @Column(name = "created_at")
  private Instant createdAt;

  @Type(type = "json")
  @Column(name = "scopes")
  private List<String> scopes;
}
