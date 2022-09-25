package com.akmal.oauth2authorizationserver.repository.authentication;

import com.akmal.oauth2authorizationserver.model.authentication.AuthenticationTransaction;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuthenticationTransactionRepository extends JpaRepository<AuthenticationTransaction, String> {

}
