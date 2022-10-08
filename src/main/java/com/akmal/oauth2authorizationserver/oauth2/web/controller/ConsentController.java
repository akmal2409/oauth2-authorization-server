package com.akmal.oauth2authorizationserver.oauth2.web.controller;

import com.akmal.oauth2authorizationserver.oauth2.web.model.Consent;
import com.akmal.oauth2authorizationserver.oauth2.web.model.ConsentRequest;
import com.akmal.oauth2authorizationserver.service.v1.auth.ConsentService;
import java.io.IOException;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

@Controller
@RequestMapping("/consent")
@RequiredArgsConstructor
public class ConsentController {

  private final ConsentService consentService;
  private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

  @GetMapping
  public ModelAndView getConsentPage(
      @RequestParam(name = "grant_scope_ids") List<Integer> grantScopeIds,
      @RequestParam(name = "target") String targetUrl,
      @RequestParam(name = "client_id") String clientId
  ) {
    final ConsentRequest request = consentService.findPendingAndGrantedScopesByClientId(clientId, grantScopeIds);

    final var model = new ModelAndView("consent");
    model.addObject("grantedScopes",request.grantedScopes());
    model.addObject("pendingScopes", request.pendingScopes());
    model.addObject("clientName", request.clientName());
    model.addObject("targetUrl", targetUrl);
    model.addObject("consent", new Consent(targetUrl, clientId, request.pendingScopes()));
    return model;
  }

  @PostMapping
  public void confirmScopeSelection(@ModelAttribute Consent consent, HttpServletRequest httpServletRequest,
      HttpServletResponse httpServletResponse) throws IOException {
    System.out.println("Consent" + consent);
    this.consentService.grantScopes(consent);
    this.redirectStrategy.sendRedirect(httpServletRequest, httpServletResponse, consent.getTargetUrl());
  }
}
