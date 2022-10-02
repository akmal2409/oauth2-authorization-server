package com.akmal.oauth2authorizationserver.model;

import com.akmal.oauth2authorizationserver.model.user.User;
import java.time.Instant;
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

@Entity
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Table(name = "sessions")
public class Session {

  @Id
  @Column(name = "id")
  private String id;

  @Column(name = "expires_at")
  private Instant expiresAt;

  @Column(name = "created_at")
  private Instant createdAt;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "sub", referencedColumnName = "sub")
  private User user;

  @Column(name = "remote_address")
  private String remoteAddress;
}
