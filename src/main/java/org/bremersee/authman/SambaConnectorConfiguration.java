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

package org.bremersee.authman;

import javax.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.bremersee.authman.domain.OAuth2ClientRepository;
import org.bremersee.authman.security.oauth2.client.OAuth2AccessTokenProvider;
import org.bremersee.authman.security.oauth2.client.OAuth2CredentialsClient;
import org.bremersee.smbcon.client.SambaConnectorClient;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @author Christian Bremer
 */
@Configuration
@EnableConfigurationProperties(SambaConnectorProperties.class)
@ConditionalOnProperty(prefix = "bremersee.samba-connector", name = "name")
@EnableFeignClients(basePackageClasses = {
    SambaConnectorClient.class
})
@Slf4j
public class SambaConnectorConfiguration {

  private final SambaConnectorProperties properties;

  @Autowired
  public SambaConnectorConfiguration(SambaConnectorProperties properties) {
    this.properties = properties;
  }

  @PostConstruct
  public void init() {
    log.info("Using REAL samba connector !!!");
  }

  @Bean(name = "sambaConnectorAccessTokenProvider")
  public OAuth2AccessTokenProvider sambaConnectorAccessTokenProvider(
      final ObjectProvider<RestTemplateBuilder> restTemplateBuilder,
      final ObjectProvider<OAuth2ClientRepository> clientRepository) {

    log.info("Creating access token provider for samba connector: {}", properties);
    return new OAuth2CredentialsClient(
        restTemplateBuilder.getIfAvailable(),
        properties.getTokenEndpoint(),
        clientRepository.getIfAvailable(),
        properties.getClientId(),
        properties.getUsername(),
        properties.getPassword());
  }

}
