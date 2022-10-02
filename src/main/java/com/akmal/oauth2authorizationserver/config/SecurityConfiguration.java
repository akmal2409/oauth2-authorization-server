package com.akmal.oauth2authorizationserver.config;

import com.akmal.oauth2authorizationserver.internal.security.filter.CustomUsernamePasswordAuthenticationFilter;
import com.akmal.oauth2authorizationserver.service.v1.auth.UserCredentialsAuthenticationProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@RequiredArgsConstructor
public class SecurityConfiguration {
  private final AuthenticationProperties authProps;
  private static final String[] WHITELISTED_RESOURCES = new String[]{"/resources/**", "/static/**", "/styles/**", "/assets/**", "/css/**", "/js/**", "/img/**", "/icon/**"};


  @Bean
  SecurityFilterChain filterChain(HttpSecurity http,
      CustomUsernamePasswordAuthenticationFilter authFilter,
      @Qualifier("federatedAuthenticationEntryPoint") AuthenticationEntryPoint federatedAuthenticationEntryPoint) throws Exception {

    return http
               .sessionManagement(sessions -> sessions.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
               .authorizeRequests(customizer -> customizer
                                                    .antMatchers(WHITELISTED_RESOURCES).permitAll()
                                                    .antMatchers(this.authProps.getLoginUrl(), this.authProps.getLoginProcessUrl()).permitAll()
                                                    .anyRequest().authenticated())
               .addFilter(authFilter)
               .exceptionHandling(customizer -> customizer.defaultAuthenticationEntryPointFor(
                   federatedAuthenticationEntryPoint,
                   new AntPathRequestMatcher("/")))
               .build();
  }

  @Bean
  AuthenticationManager authenticationManager(HttpSecurity http,
      UserCredentialsAuthenticationProvider userCredentialsAuthenticationProvider,
      @Qualifier("oAuth2WebFlowRequestAuthenticationProvider") AuthenticationProvider oAuth2WebFlowRequestAuthenticationProvider)
      throws Exception {
    final var authManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
    authManagerBuilder.authenticationProvider(userCredentialsAuthenticationProvider);
    authManagerBuilder.authenticationProvider(oAuth2WebFlowRequestAuthenticationProvider);
    return authManagerBuilder.build();
  }
}
