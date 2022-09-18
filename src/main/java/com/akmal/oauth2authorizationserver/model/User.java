package com.akmal.oauth2authorizationserver.model;

import java.time.Instant;
import java.util.Objects;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.Hibernate;

@Entity
@Getter
@Setter
@ToString
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "Users", schema = "public")
public class User {

  @Id
  @Column(name = "sub", columnDefinition = "bpchar(36)")
  private String sub;
  @Column(name = "name")
  @NotNull
  private String name;
  @Column(name = "username")
  @NotNull
  private String username;
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
//  @UpdateTimestamp
  private Instant updatedAt;

  @Column(name = "created_at")
  @NotNull
//  @CreationTimestamp
  private Instant createdAt;
  @Column(name = "email")
  private String email;
  @Column(name = "phone_number")
  private String phoneNumber;
  @Column(name = "email_verified")
  private boolean emailVerified;

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
