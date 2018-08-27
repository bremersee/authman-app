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

package org.bremersee.smbcon.client;

import feign.RequestInterceptor;
import lombok.extern.slf4j.Slf4j;
import org.bremersee.authman.SambaConnectorProperties;
import org.bremersee.authman.security.oauth2.client.OAuth2AccessTokenProvider;
import org.bremersee.authman.security.oauth2.client.OAuth2FeignRequestInterceptor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @author Christian Bremer
 */
@Configuration
@EnableConfigurationProperties(SambaConnectorProperties.class)
@Slf4j
@SuppressWarnings({"SpringJavaInjectionPointsAutowiringInspection", "SpringFacetCodeInspection"})
public class SambaConnectorClientConfiguration {

  @Bean(name = "sambaConnectorRequestInterceptor")
  public RequestInterceptor sambaConnectorRequestInterceptor(
      @Qualifier("sambaConnectorAccessTokenProvider") OAuth2AccessTokenProvider tokenProvider) {

    log.info("Creating feign request interceptor for samba connector client.");
    return new OAuth2FeignRequestInterceptor(tokenProvider);
  }

}
