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

package org.bremersee.authman.security.authentication.facebook;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bremersee.authman.security.authentication.ForeignUserProfile;
import org.bremersee.authman.security.authentication.ForeignUserProfileParser;
import org.bremersee.authman.security.authentication.OAuth2AuthenticationException;
import org.bremersee.authman.security.authentication.OAuth2AuthenticationProperties;

/**
 * @author Christian Bremer
 */
@RequiredArgsConstructor
@Slf4j
public class FacebookUserProfileParser implements ForeignUserProfileParser {

  private final OAuth2AuthenticationProperties properties;

  private final ObjectMapper objectMapper;

  @Override
  public String getProvider() {
    return properties.getProvider();
  }

  @Override
  public ForeignUserProfile parseForeignUserProfile(byte[] profileBytes) {
    try {
      return objectMapper.readValue(profileBytes, FacebookUserProfile.class);
    } catch (Exception e) {
      log.error("Parsing facebook user profile failed.", e);
      throw new OAuth2AuthenticationException("Parsing facebook user profile failed.", e);
    }
  }
}
