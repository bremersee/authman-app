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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.NotNull;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AbstractAuthenticationToken;

/**
 * @author Christian Bremer
 */
@ToString(callSuper = true)
@EqualsAndHashCode(callSuper = true)
@Slf4j
public class OAuth2AuthenticationToken extends AbstractAuthenticationToken implements
    Serializable {

  private static final long serialVersionUID = 1399153287223114368L;

  private static final String SESSION_ATTRIBUTE_NAME = "bremersee.OAuth2AuthenticationToken";

  @Getter
  private String provider;

  @Getter
  private CodeExchangeResponse credentials;

  @Getter
  private ForeignUserProfile principal;

  @Getter
  private Set<String> grantedScopes;

  OAuth2AuthenticationToken(
      @NotNull final String provider,
      @NotNull final CodeExchangeResponse credentials,
      @NotNull final ForeignUserProfile principal,
      final Set<String> grantedScopes) {

    super(new ArrayList<>());
    this.provider = provider;
    this.credentials = credentials;
    this.principal = principal;
    this.grantedScopes = grantedScopes;
  }

  OAuth2AuthenticationToken(@NotNull final OAuth2AuthenticationToken original) {
    this(
        original.provider,
        original.credentials,
        original.principal,
        original.getGrantedScopes());
  }

  void saveInSession(@NotNull final HttpServletRequest request) {
    log.debug("Saving OAuth2 authentication token [provider = {}, foreignUid = %s] in session.",
        provider,
        principal == null ? null : principal.getName());
    request.getSession(true).setAttribute(SESSION_ATTRIBUTE_NAME, this);
  }

  public static OAuth2AuthenticationToken loadFromSession(
      @NotNull final HttpServletRequest request) {

    return (OAuth2AuthenticationToken) request.getSession(true)
        .getAttribute(SESSION_ATTRIBUTE_NAME);
  }

  static void removeFromSession(@NotNull final HttpServletRequest request) {

    log.debug("Removing OAuth2 authentication token from in session.");
    if (request.getSession() != null) {
      request.getSession(true).removeAttribute(SESSION_ATTRIBUTE_NAME);
    }
  }

}
