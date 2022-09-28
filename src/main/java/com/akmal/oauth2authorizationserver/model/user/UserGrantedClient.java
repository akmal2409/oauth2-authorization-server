package com.akmal.oauth2authorizationserver.model.user;

import com.akmal.oauth2authorizationserver.model.client.Scope;
import com.akmal.oauth2authorizationserver.model.user.UserGrantedClient.PrimaryKey;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.Id;
import javax.persistence.IdClass;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * The class represents the link between the user entity and the clients it granted access to. This
 * of course includes the list of scopes and client_id
 */
@Entity
@Table(name = "User_granted_clients")
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@IdClass(PrimaryKey.class)
public class UserGrantedClient {

  @NoArgsConstructor
  @AllArgsConstructor
  @EqualsAndHashCode
  public static class PrimaryKey implements Serializable {
    private String sub;
    private String clientId;
  }

  @Id
  @Column(name = "sub")
  private String sub;

  @Id
  @Column(name = "client_id")
  private String clientId;


  @ManyToMany(fetch = FetchType.EAGER)
  @JoinTable(
      name = "User_granted_client_scopes",
      joinColumns = {
          @JoinColumn(name = "sub", referencedColumnName = "sub"),
          @JoinColumn(name = "client_id", referencedColumnName = "client_id")
      },
      inverseJoinColumns = @JoinColumn(name = "scope_id", referencedColumnName = "id")
  )
  private List<Scope> grantedScopes = new ArrayList<>();
}
