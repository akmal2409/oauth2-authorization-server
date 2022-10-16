package com.akmal.oauth2authorizationserver.repository;

import com.akmal.oauth2authorizationserver.model.client.Scope;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface ScopeRepository extends JpaRepository<Scope, Integer> {

  @Query("SELECT s FROM Scope s WHERE s.oidcScope = true")
  List<Scope> findAllOidcScopes();

  @Query("SELECT s.oidcScope FROM Scope s WHERE s.id = :scopeId")
  boolean isOidcScopeById(@Param("scopeId") int scopeId);

  List<Scope> findAllByNameIsIn(List<String> scopeNames);

  @Query(value = "SELECT s.id, s.name, s.is_oidc_scope, s.description "
                     + "FROM Scopes S INNER JOIN client_scopes cs ON S.id = cs.scope_id "
                     + "WHERE client_id = :clientId", nativeQuery = true)
  List<Scope> findAllByClientId(@Param("clientId") String clientId);
}
