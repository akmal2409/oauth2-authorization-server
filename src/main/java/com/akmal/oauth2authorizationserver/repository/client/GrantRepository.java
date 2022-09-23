package com.akmal.oauth2authorizationserver.repository.client;

import com.akmal.oauth2authorizationserver.model.client.Grant;
import com.akmal.oauth2authorizationserver.model.client.GrantType;
import org.springframework.data.jpa.repository.JpaRepository;

public interface GrantRepository extends JpaRepository<Grant, GrantType> {

}
