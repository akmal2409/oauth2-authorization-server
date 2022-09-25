package com.akmal.oauth2authorizationserver.model.authentication;

import com.vladmihalcea.hibernate.type.json.JsonBinaryType;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
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
import lombok.With;
import org.hibernate.annotations.Type;
import org.hibernate.annotations.TypeDef;
import org.hibernate.annotations.TypeDefs;
import org.springframework.util.StringUtils;

@Entity
@AllArgsConstructor
@NoArgsConstructor
@Getter @Setter
@TypeDefs({
              @TypeDef(name = "json", typeClass = JsonBinaryType.class)
})
@With
@Table(name = "Authentication_transactions", schema = "public")
public class AuthenticationTransaction {

  @Id
  @Column(name = "id")
  private String id;

  @Column(name = "client_id")
  private String clientId;

  @Column(name = "redirect_uri")
  private String redirectUri;

  @Column(name = "response_type")
  @Enumerated(EnumType.STRING)
  private AuthResponseType responseType;

  @Column(name = "state")
  private String state;

  @Column(name = "code_challenge")
  private String codeChallenge;

  @Column(name = "code_challenge_method")
  @Enumerated(EnumType.STRING)
  private CodeChallengeMethod codeChallengeMethod;

  @Column(name = "nonce")
  private String nonce;

  @Column(name = "idp")
  private String idp;

  @Column(columnDefinition = "json", name = "idp_scopes")
  @Type(type = "json")
  private List<String> idpScopes;

  @Column(columnDefinition = "json", name = "scopes")
  @Type(type = "json")
  private List<String> scopes;

  @Column(name = "timestamp")
  private Instant timestamp;

  /**
   * Indicates whether transaction is local or involves a 3rd party IDP.
   * @return state
   */
  public boolean isLocal() {
    return !StringUtils.hasText(idp);
  }


  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    AuthenticationTransaction that = (AuthenticationTransaction) o;

    if (!id.equals(that.id)) {
      return false;
    }
    if (!clientId.equals(that.clientId)) {
      return false;
    }
    if (responseType != that.responseType) {
      return false;
    }
    if (!Objects.equals(state, that.state)) {
      return false;
    }
    if (!Objects.equals(codeChallenge, that.codeChallenge)) {
      return false;
    }
    if (!Objects.equals(nonce, that.nonce)) {
      return false;
    }
    if (!Objects.equals(idp, that.idp)) {
      return false;
    }
    if (!Objects.equals(idpScopes, that.idpScopes)) {
      return false;
    }
    return Objects.equals(scopes, that.scopes);
  }

  @Override
  public int hashCode() {
    int result = id.hashCode();
    result = 31 * result + clientId.hashCode();
    result = 31 * result + responseType.hashCode();
    result = 31 * result + (state != null ? state.hashCode() : 0);
    result = 31 * result + (codeChallenge != null ? codeChallenge.hashCode() : 0);
    result = 31 * result + (nonce != null ? nonce.hashCode() : 0);
    result = 31 * result + (idp != null ? idp.hashCode() : 0);
    result = 31 * result + (idpScopes != null ? idpScopes.hashCode() : 0);
    result = 31 * result + (scopes != null ? scopes.hashCode() : 0);
    return result;
  }
}
