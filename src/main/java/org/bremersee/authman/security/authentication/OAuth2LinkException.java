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

/**
 * This exception maps the {@link OAuth2AuthenticationFailureHandler} to {@code
 * /login?merge&error={reason}}.
 *
 * @author Christian Bremer
 */
class OAuth2LinkException extends AuthenticationException {

  @Getter
  private final Reason reason;

  OAuth2LinkException(final String msg, final Reason reason) {
    super(msg);
    this.reason = reason;
  }

  OAuth2LinkException(final String msg, final Throwable cause, final Reason reason) {
    super(msg, cause);
    this.reason = reason;
  }

  enum Reason {
    LOGIN_FAILED
  }

}
