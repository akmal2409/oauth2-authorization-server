package com.akmal.oauth2authorizationserver.repository;

import com.akmal.oauth2authorizationserver.model.Role;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, Integer> {

  Optional<Role> findByName(String name);
}
