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

package org.bremersee.authman.business;

import javax.validation.constraints.NotNull;
import lombok.extern.slf4j.Slf4j;
import org.bremersee.authman.domain.OAuth2ForeignTokenRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * @author Christian Bremer
 */
@Component("oauth2ForeignTokenService")
@Slf4j
public class OAuth2ForeignTokenServiceImpl implements OAuth2ForeignTokenService {

  private OAuth2ForeignTokenRepository repository;

  @Autowired
  public OAuth2ForeignTokenServiceImpl(
      OAuth2ForeignTokenRepository repository) {
    this.repository = repository;
  }

  @Override
  public boolean isAccountConnected(
      @NotNull final String userName,
      @NotNull final String provider) {

    return repository.countByUserNameAndProvider(userName, provider) > 0;
  }
}
