package com.akmal.oauth2authorizationserver.config;

import com.akmal.oauth2authorizationserver.internal.security.authentication.WebAuthenticationDetailsSource;
import com.akmal.oauth2authorizationserver.internal.security.filter.CookieIntrospectionFilter;
import com.akmal.oauth2authorizationserver.internal.security.filter.CustomUsernamePasswordAuthenticationFilter;
import com.akmal.oauth2authorizationserver.internal.security.filter.RestAuthenticationEntryPoint;
import com.akmal.oauth2authorizationserver.internal.security.provider.SessionCookieAuthenticationProvider;
import com.akmal.oauth2authorizationserver.internal.security.provider.UserCredentialsAuthenticationProvider;
import com.akmal.oauth2authorizationserver.oauth2.authprovider.OAuth2WebFlowRequestAuthenticationProvider;
import com.akmal.oauth2authorizationserver.oauth2.authprovider.token.AuthorizationCodeTokenAuthenticationProvider;
import com.akmal.oauth2authorizationserver.oauth2.authprovider.token.RefreshTokenAuthenticationProvider;
import com.akmal.oauth2authorizationserver.oauth2.rest.controller.WellKnownController;
import com.akmal.oauth2authorizationserver.oauth2.web.filter.oauth2.OAuth2AuthorizationEndpointFilter;
import com.akmal.oauth2authorizationserver.oauth2.web.filter.oauth2.OAuth2TokenRequestFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@RequiredArgsConstructor
public class SecurityConfiguration {

  private final AuthenticationProperties authProps;
  private static final String[] WHITELISTED_RESOURCES = new String[]{"/resources/**", "/static/**",
      "/styles/**", "/assets/**", "/css/**", "/js/**", "/img/**", "/icon/**", "/oauth2/token", "/error"};


  @Bean
  SecurityFilterChain filterChain(HttpSecurity http,
      CustomUsernamePasswordAuthenticationFilter authFilter,
      @Qualifier("federatedAuthenticationEntryPoint") AuthenticationEntryPoint federatedAuthenticationEntryPoint,
      RestAuthenticationEntryPoint restAuthenticationEntryPoint,
      AuthenticationManager authenticationManager,
      OAuth2AuthorizationEndpointFilter oAuth2AuthorizationEndpointFilter,
      OAuth2TokenRequestFilter oAuth2TokenRequestFilter) throws Exception {
    return http
//               .csrf(
//                   csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
               .csrf().disable()
               .sessionManagement(
                   sessions -> sessions.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
               .authorizeRequests(customizer -> customizer
                                                    .antMatchers(this.authProps.getLoginUrl(),
                                                        this.authProps.getLoginProcessUrl(),
                                                        "/test/**",
                                                        "/api/v1/**",
                                                        WellKnownController.BASE_URL + "/**")
                                                    .permitAll()
                                                    .anyRequest().authenticated())
               .addFilter(authFilter)
               .addFilterBefore(new CookieIntrospectionFilter(authenticationManager,
                       new WebAuthenticationDetailsSource()),
                   BasicAuthenticationFilter.class)
               .addFilterBefore(oAuth2TokenRequestFilter, BasicAuthenticationFilter.class)
               .addFilterAfter(oAuth2AuthorizationEndpointFilter, CookieIntrospectionFilter.class)
               .exceptionHandling(customizer -> customizer
                                                    .defaultAuthenticationEntryPointFor(
                                                        restAuthenticationEntryPoint,
                                                        new AntPathRequestMatcher("/api/**"))
                                                    .defaultAuthenticationEntryPointFor(
                                                        federatedAuthenticationEntryPoint,
                                                        new AntPathRequestMatcher("/**"))
                                                    )
               .build();
  }

  @Bean
  WebSecurityCustomizer webSecurityCustomizer() {
    return web -> web.ignoring().antMatchers(WHITELISTED_RESOURCES);
  }

  @Bean
  AuthenticationManager authenticationManager(UserCredentialsAuthenticationProvider userCredentialsAuthenticationProvider,
      OAuth2WebFlowRequestAuthenticationProvider oAuth2WebFlowRequestAuthenticationProvider,
      SessionCookieAuthenticationProvider sessionCookieAuthenticationProvider,
      AuthorizationCodeTokenAuthenticationProvider authorizationCodeTokenAuthenticationProvider,
      RefreshTokenAuthenticationProvider refreshTokenAuthenticationProvider) {
    return new ProviderManager(userCredentialsAuthenticationProvider, oAuth2WebFlowRequestAuthenticationProvider, sessionCookieAuthenticationProvider,
        authorizationCodeTokenAuthenticationProvider, refreshTokenAuthenticationProvider);
  }

}
