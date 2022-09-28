package com.akmal.oauth2authorizationserver.repository;

import com.akmal.oauth2authorizationserver.model.client.Scope;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface ScopeRepository extends JpaRepository<Scope, Integer> {

  @Query("SELECT s FROM Scopes s WHERE is_oidc_scope = true")
  List<Scope> findAllOidcScopes();
}
