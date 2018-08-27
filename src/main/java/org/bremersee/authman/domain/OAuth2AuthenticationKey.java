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

package org.bremersee.authman.domain;

import java.io.Serializable;
import javax.validation.constraints.NotNull;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.util.StringUtils;

/**
 * @author Christian Bremer
 */
@Getter
@ToString
@EqualsAndHashCode
public class OAuth2AuthenticationKey implements Serializable {

  private static final long serialVersionUID = -2122371818337212968L;

  private final String userName;

  private final String clientId;

  private final String scopes;

  public OAuth2AuthenticationKey(@NotNull final OAuth2Authentication authentication) {
    this.userName = authentication.isClientOnly() ? null : authentication.getName();
    this.clientId = authentication.getOAuth2Request().getClientId();
    if (authentication.getOAuth2Request().getScope() != null
        && !authentication.getOAuth2Request().getScope().isEmpty()) {
      this.scopes = StringUtils.collectionToDelimitedString(
          authentication.getOAuth2Request().getScope(), " ");
    } else {
      this.scopes = "";
    }
  }
}
