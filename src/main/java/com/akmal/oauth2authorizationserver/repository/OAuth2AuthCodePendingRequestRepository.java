package com.akmal.oauth2authorizationserver.repository;

import com.akmal.oauth2authorizationserver.model.OAuth2AuthorizationCodePendingRequest;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OAuth2AuthCodePendingRequestRepository extends JpaRepository<OAuth2AuthorizationCodePendingRequest, String> {

}
