package com.akmal.oauth2authorizationserver.repository.client;

import com.akmal.oauth2authorizationserver.model.client.Client;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ClientRepository extends JpaRepository<Client, String> {

}
