package com.akmal.oauth2authorizationserver.repository;

import com.akmal.oauth2authorizationserver.model.RefreshToken;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, String> {

  @Query("SELECT r from RefreshToken r JOIN FETCH r.user WHERE r.token = :token")
  Optional<RefreshToken> findByTokenJoinFetchUser(@Param("token") String token);
}
