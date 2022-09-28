package com.akmal.oauth2authorizationserver.repository;

import com.akmal.oauth2authorizationserver.model.user.UserGrantedClient;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface UserGrantedClientRepository extends JpaRepository<UserGrantedClient,
                                                                      UserGrantedClient.PrimaryKey> {
  @Query("SELECT ugc FROM UserGrantedClient ugc WHERE ugc.sub = :sub AND "
             + "ugc.clientId = :clientId")
  Optional<UserGrantedClient> findBySubAndClientId(@Param("sub") String sub, @Param("clientId") String clientId);
}
