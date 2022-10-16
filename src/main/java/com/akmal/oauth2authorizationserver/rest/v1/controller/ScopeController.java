package com.akmal.oauth2authorizationserver.rest.v1.controller;

import com.akmal.oauth2authorizationserver.rest.v1.dto.scope.ScopeCreationRequest;
import com.akmal.oauth2authorizationserver.rest.v1.dto.scope.ScopeDto;
import com.akmal.oauth2authorizationserver.service.v1.ScopeService;
import java.util.Collection;
import lombok.RequiredArgsConstructor;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(ScopeController.BASE_URL)
@RequiredArgsConstructor
public class ScopeController {

  public static final String BASE_URL = "/api/v1/scopes";
  private final ScopeService scopeService;

  @GetMapping
  public Collection<ScopeDto> findAll() {
    return this.scopeService.findAll();
  }

  @PostMapping
  public ScopeDto saveCustomScope(@Validated @RequestBody ScopeCreationRequest scopeCreationRequest) {
    return this.scopeService.saveCustomScope(scopeCreationRequest);
  }
}
