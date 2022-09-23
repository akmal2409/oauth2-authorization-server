package com.akmal.oauth2authorizationserver.validator.client;

import com.akmal.oauth2authorizationserver.exception.validation.InvalidClientConfigurationException;
import com.akmal.oauth2authorizationserver.validator.Validator;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import org.apache.commons.validator.routines.UrlValidator;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class ClientValidator implements Validator<ClientProperties> {
  private static final UrlValidator URL_VALIDATOR = new UrlValidator(new String[]{"http", "https"});
  private static final String URL_WILDCARD = "*";

  @Override
  public boolean validate(ClientProperties clientProperties) {
    if (!StringUtils.hasText(clientProperties.name())) {
      throw new InvalidClientConfigurationException("Valid client name of length >= 1", "Empty name");
    }
    this.validateUrls(clientProperties.signInRedirectUris(),
        clientProperties.signOutRedirectUris(),
        clientProperties.trustedOrigins(), clientProperties.allowWildcardsInRedirectUrls());
    this.validateGrants(clientProperties.systemWhitelistedGrants(), clientProperties.grants());

    return true;
  }

  private void validateGrants(Collection<String> systemWideAvailableGrants,
      Collection<String> selectedGrants) {
    final var grantSet = new HashSet<>(systemWideAvailableGrants);
    final var selectedGrantsCopy = new ArrayList<>(selectedGrants);

    Collections.sort(selectedGrantsCopy);

    for (int i = 0; i < selectedGrantsCopy.size(); i++) {
      if (!grantSet.contains(selectedGrantsCopy.get(i))) {
        throw new InvalidClientConfigurationException("Valid grant", String.format("Invalid grant specified: %s", selectedGrantsCopy.get(i)));
      }


      if (i > 0 && selectedGrantsCopy.get(i - 1).equals(selectedGrantsCopy.get(i))) {
        throw new InvalidClientConfigurationException("No duplicate grants", String.format("Duplicate grant is present: %s",
            selectedGrantsCopy.get(i)));
      }

    }
  }

  /**
   * Helper method that validates the collection of URLs commonly used when creating
   * and updating the client.
   *
   * @param singIn post sign-in redirect urls
   * @param singOut post sign-out redirect urls
   * @param trustedOrigins  trusted origins
   * @param allowWildcards whether to allow {@link ClientValidator#URL_WILDCARD}.
   * @throws InvalidClientConfigurationException if one of the URLs is invalid.
   */
  private void validateUrls(Collection<String> singIn,
      Collection<String> singOut, Collection<String> trustedOrigins, boolean allowWildcards) {

    if (!this.areUrlsValid(singIn, allowWildcards)) {
      throw new InvalidClientConfigurationException(constructInvalidRedirectUrlMessage(singIn,
          allowWildcards, "sign in redirect URLs"));
    }

    if (!this.areUrlsValid(singOut, allowWildcards)) {
      throw new InvalidClientConfigurationException(constructInvalidRedirectUrlMessage(singOut,
          allowWildcards, "sign out redirect URLs"));
    }

    if (!this.areUrlsValid(trustedOrigins, allowWildcards)) {
      throw new InvalidClientConfigurationException(constructInvalidRedirectUrlMessage(trustedOrigins,
          allowWildcards, "trusted origins"));
    }
  }


  /**
   * Method checks using {@link ClientValidator#URL_VALIDATOR} instance the validity of the URLs.
   * If the wildcard is encountered but was not allowed, the method will return false.
   *
   * @param urls collection of URLs.
   * @param wildcardAllowed whether to allow wildcard symbol.
   * @return validity of the collection.
   */
  private boolean areUrlsValid(Collection<String> urls, boolean wildcardAllowed) {
    for (String url: urls) {
      if (URL_WILDCARD.equals(url) && wildcardAllowed) continue;

      if (!URL_VALIDATOR.isValid(url)) return false;
    }

    return true;
  }

  private String constructInvalidRedirectUrlMessage(Collection<String> urls, boolean wildcardsAllowed, String collectionName) {
    return String.format("Valid URL with protocol either http or https in %s. "
                             + "If wildcards were used, ensure that the user allowed it. URLs=[%s] "
                             + "Allow wildcards in redirect URLs = %s", collectionName, urls, wildcardsAllowed);
  }
}
