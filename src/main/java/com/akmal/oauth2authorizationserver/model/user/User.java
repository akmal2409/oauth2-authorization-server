package com.akmal.oauth2authorizationserver.model.user;

import com.akmal.oauth2authorizationserver.crypto.jwt.Claim;
import com.akmal.oauth2authorizationserver.model.RefreshToken;
import com.akmal.oauth2authorizationserver.model.Role;
import com.akmal.oauth2authorizationserver.model.Session;
import com.akmal.oauth2authorizationserver.oauth2.config.OidcScopes;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.OneToMany;
import javax.persistence.OrderBy;
import javax.persistence.Table;
import javax.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import lombok.With;
import org.hibernate.Hibernate;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.ietf.jgss.Oid;

@Entity
@Getter
@Setter
@ToString
@AllArgsConstructor
@NoArgsConstructor
@With
@Table(name = "Users", schema = "public")
public class User {

  @Id
  @Column(name = "sub")
  private String sub;
  @Column(name = "name")
  @NotNull
  private String name;

  @Column(name = "password")
  private String password;

  @Column(name = "first_name")
  @NotNull
  private String firstName;
  @Column(name = "middle_name")
  private String middleName;
  @Column(name = "last_name")
  @NotNull
  private String lastName;
  @Column(name = "zone_info")
  private String zoneInfo;
  @Column(name = "locale")
  private String locale;
  @Column(name = "updated_at")
  @UpdateTimestamp
  private Instant updatedAt;

  @Column(name = "created_at")
  @NotNull
  @CreationTimestamp
  private Instant createdAt;
  @Column(name = "email")
  private String email;
  @Column(name = "phone_number")
  private String phoneNumber;
  @Column(name = "email_verified")
  private boolean emailVerified;

  @OneToMany(fetch = FetchType.LAZY, mappedBy = "user")
  @OrderBy("createdAt DESC")
  private List<Session> sessions;

  @OneToMany(fetch = FetchType.LAZY, mappedBy = "user")
  private List<RefreshToken> refreshTokens;

  @ManyToMany(fetch = FetchType.LAZY, cascade = CascadeType.ALL)
  @JoinTable(
      name = "User_roles",
                schema = "public",
                joinColumns = @JoinColumn(name = "user_id", referencedColumnName = "sub"),
                inverseJoinColumns = @JoinColumn(name = "role_id", referencedColumnName = "id")
  )
  private List<Role> roles = new ArrayList<>();

  public User addRole(Role role) {
    this.roles.add(role);
    return this;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || Hibernate.getClass(this) != Hibernate.getClass(o)) {
      return false;
    }
    User user = (User) o;
    return sub != null && Objects.equals(sub, user.sub);
  }

  @Override
  public int hashCode() {
    return getClass().hashCode();
  }

  public Map<String, Object> extractPropertiesBasedOnScopes(Set<String> scopes) {
    final var props = new HashMap<String, Object>();
    if (scopes.contains(OidcScopes.EMAIL)) {
      props.put("email", this.email);
    }

    if (scopes.contains(OidcScopes.PHONE)) {
      props.put("phone", this.phoneNumber);
    }

    if (scopes.contains(OidcScopes.PROFILE)) {
      props.put("name", this.name);
      props.put("first_name", this.firstName);
      props.put("middle_name", this.middleName);
      props.put("last_name", this.lastName);
      props.put("locale", this.locale);
      props.put("zone_info", this.zoneInfo);
    }

    if (scopes.contains(OidcScopes.OPENID)) {
      props.put("user_id", this.sub);
      props.put("email_verified", this.emailVerified);
    }

    return props;
  }
}
