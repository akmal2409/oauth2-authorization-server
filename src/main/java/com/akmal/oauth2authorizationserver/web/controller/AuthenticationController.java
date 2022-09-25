package com.akmal.oauth2authorizationserver.web.controller;

import com.akmal.oauth2authorizationserver.model.authentication.AuthenticationTransaction;
import com.akmal.oauth2authorizationserver.service.v1.auth.AuthenticationService;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequestMapping(AuthenticationController.BASE_URL)
@RequiredArgsConstructor
public class AuthenticationController {
  public static final String BASE_URL = "/oauth2/v1/authorize";
  private final AuthenticationService authenticationService;


  @GetMapping
  public String beginAuthenticationFlow(
      @RequestParam Map<String, String> queryParamMap
  ) {
    final var transaction = this.authenticationService
        .beginAuthenticationTransaction(queryParamMap);
    return this.getRedirectUrl(transaction);
  }

  /**
   * Returns redirect URL based on the transaction type.
   * If transaction involves external IDP, it will be redirected to appropriate middleware,
   * however, if the transaction is within local bounds, it will be handled by another controller.
   *
   * @param transaction {@link AuthenticationTransaction}.
   * @return redirect url.
   */
  private String getRedirectUrl(AuthenticationTransaction transaction) {
    if (transaction.isLocal()) {
      return String.format("redirect:/?transactionId=%s", transaction.getId());
    } else {
      return "not implemented";
    }
  }
}
