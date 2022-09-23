package com.akmal.oauth2authorizationserver.rest.v1.controller;

import com.akmal.oauth2authorizationserver.rest.v1.dto.client.ClientDto;
import com.akmal.oauth2authorizationserver.rest.v1.dto.client.SecretGenerationResponse;
import com.akmal.oauth2authorizationserver.rest.v1.dto.client.action.ClientCreateAction;
import com.akmal.oauth2authorizationserver.service.v1.client.ClientService;
import java.util.List;
import javax.validation.Valid;
import javax.validation.constraints.NotEmpty;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(ClientController.BASE_API_URL)
@RequiredArgsConstructor
public class ClientController {
  public static final String BASE_API_URL = "/api/v1/clients";
  private final ClientService clientService;

  @GetMapping
  public List<ClientDto> findAllClients() {
    return this.clientService.findAllClients();
  }

  @ResponseStatus(HttpStatus.CREATED)
  @PostMapping
  public ClientDto createClient(@RequestBody @Valid ClientCreateAction clientCreateAction) {
    return this.clientService.create(clientCreateAction);
  }

  @ResponseStatus(HttpStatus.CREATED)
  @PostMapping("/{clientId}/secrets")
  public SecretGenerationResponse generateSecret(@PathVariable @Valid @NotEmpty String clientId) {
    return this.clientService.generateSecret(clientId);
  }
}
