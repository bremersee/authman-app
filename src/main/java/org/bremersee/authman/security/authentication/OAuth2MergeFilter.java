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

import java.util.ArrayList;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.authentication.session.CompositeSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/**
 * @author Christian Bremer
 */
@Slf4j
public class OAuth2MergeFilter extends AbstractAuthenticationProcessingFilter {

  private static final String USERNAME = "username";

  private static final String PASSWORD = "password"; // NOSONAR

  private static final String NEW_USERNAME = "new_username";

  private static final String NEW_PASSWORD = "new_password"; // NOSONAR

  private static final String NEW_PASSWORD_REPETITION = "new_password_repetition"; // NOSONAR

  public OAuth2MergeFilter() {
    super(new AntPathRequestMatcher("/merge", "POST"));

    setAuthenticationSuccessHandler(new OAuth2AuthenticationSuccessHandler());

    final List<SessionAuthenticationStrategy> delegateStrategies = new ArrayList<>();
    delegateStrategies.add(new ChangeSessionIdAuthenticationStrategy());
    setSessionAuthenticationStrategy(
        new CompositeSessionAuthenticationStrategy(delegateStrategies));

    setAuthenticationFailureHandler(new OAuth2AuthenticationFailureHandler());
  }

  @Override
  public Authentication attemptAuthentication(
      final HttpServletRequest request,
      final HttpServletResponse response) {

    log.debug("Merging OAuth2 authentication with local account ...");

    OAuth2AuthenticationToken storedOAuth2AuthToken = OAuth2AuthenticationToken
        .loadFromSession(request);
    if (storedOAuth2AuthToken == null) {
      throw new OAuth2AuthenticationException(
          "OAuth2 authentication token must be present in the session.");
    }

    final Authentication authRequest;
    if (StringUtils.isNotBlank(request.getParameter(USERNAME))) {
      authRequest = linkAccounts(storedOAuth2AuthToken, request);

    } else if (StringUtils.isNotBlank(request.getParameter(NEW_USERNAME))) {
      authRequest = createAccountAndLink(storedOAuth2AuthToken, request);

    } else {
      authRequest = createAccountSilentlyAndLink(storedOAuth2AuthToken);
    }
    return getAuthenticationManager().authenticate(authRequest);
  }

  private Authentication linkAccounts(
      final OAuth2AuthenticationToken storedOAuth2AuthToken,
      final HttpServletRequest request) {

    final String username = request.getParameter(USERNAME);
    final String password = request.getParameter(PASSWORD);
    return new OAuth2LinkAuthenticationToken(storedOAuth2AuthToken, username, password);
  }

  private Authentication createAccountAndLink(
      final OAuth2AuthenticationToken storedOAuth2AuthToken,
      final HttpServletRequest request) {

    final String username = request.getParameter(NEW_USERNAME);
    final String password = request.getParameter(NEW_PASSWORD);
    final String passwordRepetition = request.getParameter(NEW_PASSWORD_REPETITION);
    return new OAuth2CreateAccountAndLinkAuthenticationToken(
        storedOAuth2AuthToken,
        username,
        password,
        passwordRepetition);
  }

  private Authentication createAccountSilentlyAndLink(
      final OAuth2AuthenticationToken storedOAuth2AuthToken) {

    return new OAuth2CreateAccountSilentlyAndLinkAuthenticationToken(storedOAuth2AuthToken);
  }


}
