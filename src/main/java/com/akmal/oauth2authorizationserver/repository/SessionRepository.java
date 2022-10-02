package com.akmal.oauth2authorizationserver.repository;

import com.akmal.oauth2authorizationserver.model.Session;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SessionRepository extends JpaRepository<Session, String> {

}
