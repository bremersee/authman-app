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

import javax.servlet.http.HttpServletRequest;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Validate;

/**
 * Saves and loads the OAuth2 state parameter in the session. The state parameter is a kind of CSRF
 * protection in the OAuth2 protocol.
 *
 * @author Christian Bremer
 */
@Slf4j
@RequiredArgsConstructor
public class OAuth2StateCache {

  @NonNull
  private final String keyName;

  public void saveState(final HttpServletRequest request, final String state) {
    Validate.notNull(request, "Http request must not be null.");
    request.getSession(true).setAttribute(keyName, state);
    log.debug("State saved in session with ID {}", request.getSession(true).getId());
  }

  public String getState(final HttpServletRequest request) {
    Validate.notNull(request, "Http request must not be null.");
    String state = (String) request.getSession(true).getAttribute(keyName);
    if (StringUtils.isBlank(state)) {
      log.warn("State was not found in session with ID {}", request.getSession(true).getId());
    }
    return state;
  }

  public void removeState(final HttpServletRequest request) {
    if (request != null && request.getSession() != null) {
      request.getSession(true).removeAttribute(keyName);
    }
  }

}
