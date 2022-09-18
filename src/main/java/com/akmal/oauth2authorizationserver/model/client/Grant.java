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
@Table(name = "Grants", schema = "public")
public class Grant {
  @Id
  @Enumerated(EnumType.STRING)
  @Column(name = "type")
  private GrantType type;
}
