package com.akmal.oauth2authorizationserver.repository;

import com.akmal.oauth2authorizationserver.model.Session;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface SessionRepository extends JpaRepository<Session, String> {

  @Query("SELECT DISTINCT s FROM Session s JOIN FETCH s.user WHERE s.id = :id")
  Optional<Session> findByIdWithUser(@Param("id") String id);
}
