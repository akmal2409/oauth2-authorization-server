package com.akmal.oauth2authorizationserver.oauth2.web.controller;

import com.akmal.oauth2authorizationserver.service.v1.auth.AuthenticationService;
import com.akmal.oauth2authorizationserver.oauth2.web.model.SignUpModel;
import java.util.Map;
import javax.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

@Controller
@RequestMapping("/sign-up")
@RequiredArgsConstructor
public class SingUpController {

  private final AuthenticationService authenticationService;

  @GetMapping
  public ModelAndView getSignUpForm() {
    return new ModelAndView("sign-up", Map.of("signUpModel", new SignUpModel()));
  }

  @PostMapping
  public ModelAndView signUp(@Valid @ModelAttribute SignUpModel signUpModel) {
    this.authenticationService.createUser(signUpModel);
    return new ModelAndView("redirect:/");
  }
}
