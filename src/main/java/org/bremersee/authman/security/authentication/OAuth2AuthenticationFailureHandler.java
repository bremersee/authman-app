/*
 * Copyright 2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bremersee.authman.security.authentication;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

/**
 * @author Christian Bremer
 */
@Slf4j
public class OAuth2AuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

  private final AuthenticationFailureHandler mustBeLinkedHandler;

  OAuth2AuthenticationFailureHandler() {
    super("/login?error");
    mustBeLinkedHandler = new SimpleUrlAuthenticationFailureHandler("/merge");
  }

  @Override
  public void onAuthenticationFailure(HttpServletRequest request,
      HttpServletResponse response, AuthenticationException exception)
      throws IOException, ServletException {

    if (exception instanceof OAuth2MustBeLinkedException) {
      ((OAuth2MustBeLinkedException) exception).getAuthenticationToken().saveInSession(request);
      mustBeLinkedHandler.onAuthenticationFailure(request, response, exception);

    } else if (exception instanceof OAuth2LinkException) {
      OAuth2LinkException e = (OAuth2LinkException) exception;
      OAuth2LinkException.Reason r = e.getReason();
      String url = "/merge?display=view1&error" + toUrlParameterValue(r);
      log.debug("An exception occurred while linking with an existing account, redirecting to {}",
          url);
      (new SimpleUrlAuthenticationFailureHandler(url))
          .onAuthenticationFailure(request, response, exception);

    } else if (exception instanceof OAuth2CreateAndLinkException) {
      OAuth2CreateAndLinkException e = (OAuth2CreateAndLinkException) exception;
      OAuth2CreateAndLinkException.Reason r = e.getReason();
      String url = "/merge?display=view2&error" + toUrlParameterValue(r);
      log.debug("An exception occurred while linking with a new account, redirecting to {}", url);
      (new SimpleUrlAuthenticationFailureHandler(url))
          .onAuthenticationFailure(request, response, exception);

    } else {
      log.debug("A general exception occurred while linking, redirecting to /login?error");
      super.onAuthenticationFailure(request, response, exception);
    }
  }

  private String toUrlParameterValue(OAuth2LinkException.Reason r) {
    if (r == null) {
      return "";
    }
    try {
      return "=" + URLEncoder.encode(r.name(), StandardCharsets.UTF_8.name());
    } catch (IOException e) { // NOSONAR
      return r.name();
    }
  }

  private String toUrlParameterValue(OAuth2CreateAndLinkException.Reason r) {
    if (r == null) {
      return "";
    }
    try {
      return "=" + URLEncoder.encode(r.name(), StandardCharsets.UTF_8.name());
    } catch (IOException e) { // NOSONAR
      return r.name();
    }
  }

}
