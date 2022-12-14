package com.akmal.oauth2authorizationserver.repository.client;

import com.akmal.oauth2authorizationserver.model.client.Client;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface ClientRepository extends JpaRepository<Client, String> {

  @Query("SELECT c FROM Client c JOIN FETCH c.allowedScopes WHERE c.clientId = :clientId")
  Optional<Client> findByIdJoinedWithAllowedScopes(@Param("clientId") String clientId);

  @Modifying
  @Query(value = "DELETE FROM public.Client_scopes WHERE client_id = :clientId AND scope_id = :scopeId", nativeQuery = true)
  void deleteScopeByClientIdAndScopeId(@Param("clientId") String clientId, @Param("scopeId") int scopeId);
}
