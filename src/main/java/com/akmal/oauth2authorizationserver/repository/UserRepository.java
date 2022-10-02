package com.akmal.oauth2authorizationserver.repository;

import com.akmal.oauth2authorizationserver.model.user.User;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface UserRepository extends JpaRepository<User, String> {


  @Query(value = "SELECT CASE WHEN (count(u.sub) > 0) THEN true else false end FROM User u "
                     + "WHERE u.email = :email")
  Boolean hasEmail(@Param("email") String email);

  Optional<User> findByEmail(String email);
}
