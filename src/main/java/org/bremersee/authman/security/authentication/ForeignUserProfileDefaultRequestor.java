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

import java.nio.charset.StandardCharsets;
import javax.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

/**
 * @author Christian Bremer
 */
@RequiredArgsConstructor
@Slf4j
public class ForeignUserProfileDefaultRequestor implements ForeignUserProfileRequestor {

  private final OAuth2AuthenticationProperties properties;

  private final ForeignUserProfileParser foreignUserProfileParser;

  private RestTemplateBuilder restTemplateBuilder = new RestTemplateBuilder();

  public void setRestTemplateBuilder(final RestTemplateBuilder restTemplateBuilder) {
    if (restTemplateBuilder != null) {
      this.restTemplateBuilder = restTemplateBuilder;
    }
  }

  public ForeignUserProfileDefaultRequestor restTemplateBuilder(
      final RestTemplateBuilder restTemplateBuilder) {
    setRestTemplateBuilder(restTemplateBuilder);
    return this;
  }

  @Override
  public ForeignUserProfile getForeignUserProfile(
      @NotNull final CodeExchangeResponse credentials) {

    final RestTemplate restTemplate = restTemplateBuilder.build();
    final ResponseEntity<byte[]> response = restTemplate.getForEntity(
        buildProfileUrlTemplate(),
        byte[].class,
        credentials.getAccessToken());
    final byte[] profileContent = response.getBody();
    if (log.isDebugEnabled()) {
      log.debug("Foreign profile from provider [{}]: {}", properties.getProvider(),
          new String(profileContent, StandardCharsets.UTF_8));
    }
    final ForeignUserProfile profile = foreignUserProfileParser
        .parseForeignUserProfile(profileContent);
    if (log.isDebugEnabled()) {
      log.debug("Parsed foreign profile: {}", profile);
    }
    return profile;
  }

  private String buildProfileUrlTemplate() {
    return properties.getApiBaseUrl() + properties.getProfilePathTemplate();
  }

}
