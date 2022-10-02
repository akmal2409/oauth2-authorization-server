package com.akmal.oauth2authorizationserver.model.client;

import java.util.ArrayList;
import java.util.List;
import javax.persistence.CollectionTable;
import javax.persistence.Column;
import javax.persistence.ElementCollection;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.Table;
import javax.persistence.Transient;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.With;
import org.springframework.data.domain.Persistable;


@Entity
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@With
@Table(name = "Clients", schema = "public")
public class Client implements Persistable<String> {
  @Id
  @Column(name = "client_id")
  private String clientId;

  @Column(name = "name")
  private String name;

  @Column(name = "client_secret")
  private String clientSecret;

  @ManyToMany(fetch = FetchType.EAGER)
  @JoinTable(
      name = "Client_grants",
      joinColumns = @JoinColumn(name = "client_id", referencedColumnName = "client_id"),
      inverseJoinColumns = @JoinColumn(name = "grant_type", referencedColumnName = "type")
  )
  private List<Grant> grants = new ArrayList<>();

  @ElementCollection(fetch = FetchType.LAZY)
  @CollectionTable(name = "Client_sign_in_redirect_uris",
      joinColumns = @JoinColumn(name = "client_id", referencedColumnName = "client_id"))
  @Column(name = "uri")
  private List<String> signInRedirectUris = new ArrayList<>();

  @ElementCollection(fetch = FetchType.LAZY)
  @CollectionTable(name = "Client_sign_out_redirect_uris",
      joinColumns = @JoinColumn(name = "client_id", referencedColumnName = "client_id"))
  @Column(name = "uri")
  private List<String> signOutRedirectUris = new ArrayList<>();

  @ElementCollection(fetch = FetchType.LAZY)
  @CollectionTable(name = "Client_trusted_origins_uris",
      joinColumns = @JoinColumn(name = "client_id", referencedColumnName = "client_id"))
  @Column(name = "uri")
  private List<String> trustedOrigins = new ArrayList<>();

  @Column(name = "require_user_consent")
  private boolean requireUserConsent;

  @Column(name = "allow_wildcards_in_redirect_urls")
  private boolean allowWildcardsInRedirectUrls;

  @ManyToMany(fetch = FetchType.LAZY)
  @JoinTable(
      name = "Client_scopes",
      schema = "public",
      joinColumns = @JoinColumn(name = "client_id", referencedColumnName = "client_id"),
      inverseJoinColumns = @JoinColumn(name = "scope_id", referencedColumnName = "id")
  )
  private List<Scope> allowedScopes = new ArrayList<>();

  @Transient
  private boolean newEntity;


  public void addGrant(Grant grant) {
    this.grants.add(grant);
  }

  @Override
  public String getId() {
    return this.clientId;
  }

  @Override
  public boolean isNew() {
    return this.newEntity;
  }

  public boolean isWebAuthFlowAllowed() {
    return this.grants.stream()
               .anyMatch(g -> GrantType.AUTHORIZATION_CODE_PKCE.equals(g.getType()));
  }
}
