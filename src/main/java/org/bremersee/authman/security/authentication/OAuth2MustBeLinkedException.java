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

import lombok.Getter;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.Assert;

/**
 * @author Christian Bremer
 */
class OAuth2MustBeLinkedException extends AuthenticationException {

  @Getter
  private final OAuth2AuthenticationToken authenticationToken;

  OAuth2MustBeLinkedException(String msg, OAuth2AuthenticationToken authenticationToken) {
    super(msg);
    this.authenticationToken = authenticationToken;
    Assert.notNull(authenticationToken, "OAuth2 authentication token must not be null.");
  }

}
