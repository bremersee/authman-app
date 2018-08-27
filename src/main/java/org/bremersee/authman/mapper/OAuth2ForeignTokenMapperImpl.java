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

package org.bremersee.authman.mapper;

import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashSet;
import javax.validation.constraints.NotNull;
import lombok.extern.slf4j.Slf4j;
import org.bremersee.authman.domain.OAuth2ForeignToken;
import org.bremersee.authman.security.authentication.CodeExchangeResponse;
import org.bremersee.authman.security.authentication.OAuth2AuthenticationToken;
import org.springframework.util.StringUtils;

/**
 * @author Christian Bremer
 */
@Slf4j
public class OAuth2ForeignTokenMapperImpl implements OAuth2ForeignTokenMapper {

  @Override
  public void updateForeignToken(
      @NotNull final OAuth2ForeignToken destination,
      @NotNull final OAuth2AuthenticationToken source) {

    updateForeignToken(
        destination,
        source.getProvider(),
        null,
        source.getPrincipal().getName(),
        source.getGrantedScopes(),
        source.getCredentials());
  }

  @Override
  public void updateForeignToken(
      @NotNull final OAuth2ForeignToken destination,
      @NotNull final String provider,
      final String userName,
      @NotNull final String foreignUserName,
      final Collection<String> scopes,
      @NotNull final CodeExchangeResponse codeResponse) {

    destination.setProvider(provider);
    if (StringUtils.hasText(userName)) {
      destination.setUserName(userName);
    }
    destination.setForeignUserName(foreignUserName);
    if (scopes != null) {
      destination.setScopes(new LinkedHashSet<>(scopes));
    }
    destination.setAccessToken(codeResponse.getAccessToken());
    destination.setTokenType(codeResponse.getTokenType());
    destination.setRefreshToken(codeResponse.getRefreshToken());
    final String expiresSecondsStr = codeResponse.getExpiresIn();
    if (StringUtils.hasText(expiresSecondsStr)) {
      try {
        final Long expiresSeconds = Long.parseLong(expiresSecondsStr);
        destination.setExpiresAt(new Date(System.currentTimeMillis() + expiresSeconds));

      } catch (final NumberFormatException nfe) {
        destination.setExpiresAt(null);
        if (log.isWarnEnabled()) {
          log.warn(String.format("msg=[Parsing expires in [%s] failed.]", expiresSecondsStr), nfe);
        }
      }
    }
    log.debug("msg=[Mapping authentication token to foreign token: {}", destination);
  }

}
