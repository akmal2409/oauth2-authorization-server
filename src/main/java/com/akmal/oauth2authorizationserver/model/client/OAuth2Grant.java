package com.akmal.oauth2authorizationserver.model.client;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.Id;
import javax.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "OAuth_2_grants", schema = "public")
public class OAuth2Grant {
  @Id
  @Enumerated(EnumType.STRING)
  @Column(name = "type")
  private OAuth2GrantType type;
}
