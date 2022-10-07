package com.akmal.oauth2authorizationserver.oauth2.web.filter.oauth2;

import javax.servlet.http.HttpServletRequest;
import org.springframework.util.StringUtils;

public class RequestUtils {

  /**
   * Returns complete request URL with query parameters.
   * @param request
   * @return
   */
  public static String getFullRequestUrl(HttpServletRequest request) {
    final var stringBuilder = new StringBuilder(request.getRequestURL().toString());

    if (StringUtils.hasText(request.getQueryString())) {
      stringBuilder.append("?").append(request.getQueryString());
    }

    return stringBuilder.toString();
  }
}
