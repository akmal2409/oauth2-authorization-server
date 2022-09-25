package com.akmal.oauth2authorizationserver.web.controller;

import com.akmal.oauth2authorizationserver.web.model.SignInModel;
import java.util.Optional;
import javax.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

@Controller
@RequestMapping("/")
@Slf4j
public class SingInController {

  @GetMapping
  public ModelAndView getSignInPage(@RequestParam(required = false) Optional<String> transactionId) {
    final var model = new ModelAndView("sign-in.html");
    model.addObject("transactionId", transactionId);
    model.addObject("signInModel", new SignInModel());
    return model;
  }

  @PostMapping
  @ResponseBody
  public String onSignIn(@Valid @ModelAttribute("signInModel") SignInModel signInModel) {
    return "hey";
  }
}
