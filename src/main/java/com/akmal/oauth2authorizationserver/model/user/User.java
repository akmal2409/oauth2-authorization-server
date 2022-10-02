package com.akmal.oauth2authorizationserver.model.user;

import com.akmal.oauth2authorizationserver.model.Role;
import com.akmal.oauth2authorizationserver.model.Session;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.OneToMany;
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
  private List<Session> sessions;

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
}
