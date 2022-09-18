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
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;


@Entity
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Table(name = "Clients", schema = "public")
public class Client {
  @Id
  @Column(name = "client_id", columnDefinition = "bpchar(36)")
  private String clientId;

  @Column(name = "name")
  private String name;

  @Column(name = "client_secret")
  private String clientSecret;

  @ManyToMany(fetch = FetchType.EAGER)
  @JoinTable(
      name = "Client_grants",
      schema = "public",
      joinColumns = @JoinColumn(name = "client_id", referencedColumnName = "client_id")       ,
      inverseJoinColumns = @JoinColumn(name = "grant_type", referencedColumnName = "type")
  )
  private List<Grant> grants = new ArrayList<>();

  @ElementCollection
  @CollectionTable(name = "Client_sign_in_redirect_uris",
    joinColumns = @JoinColumn(name = "client_id", referencedColumnName = "client_id"))
  @Column(name = "uri")
  private List<String> signInRedirectUris = new ArrayList<>();

  @ElementCollection
  @CollectionTable(name = "Client_sign_out_redirect_uris",
      joinColumns = @JoinColumn(name = "client_id", referencedColumnName = "client_id"))
  @Column(name = "uri")
  private List<String> signOutRedirectUris = new ArrayList<>();

  @ElementCollection
  @CollectionTable(name = "Client_trusted_origins_uris",
      joinColumns = @JoinColumn(name = "client_id", referencedColumnName = "client_id"))
  @Column(name = "uri")
  private List<String> trustedOrigins = new ArrayList<>();

  @Column(name = "require_user_consent")
  private boolean requireUserConsent;


  public void addGrant(Grant grant) {
    this.grants.add(grant);
  }
}
