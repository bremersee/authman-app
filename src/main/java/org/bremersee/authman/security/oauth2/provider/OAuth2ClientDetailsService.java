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

package org.bremersee.authman.security.oauth2.provider;

import javax.validation.constraints.NotNull;
import lombok.extern.slf4j.Slf4j;
import org.bremersee.authman.domain.OAuth2Client;
import org.bremersee.authman.domain.OAuth2ClientRepository;
import org.bremersee.authman.domain.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.stereotype.Component;

/**
 * @author Christian Bremer
 */
@Component("oauth2ClientDetailsService")
@Slf4j
public class OAuth2ClientDetailsService implements ClientDetailsService {

  private final OAuth2ClientRepository clientRepository;

  private final RoleRepository roleRepository;

  @Autowired
  public OAuth2ClientDetailsService(
      OAuth2ClientRepository clientRepository,
      RoleRepository roleRepository) {
    this.clientRepository = clientRepository;
    this.roleRepository = roleRepository;
  }

  @Override
  public ClientDetails loadClientByClientId(@NotNull final String clientId) {

    if (log.isDebugEnabled()) {
      log.debug("Loading client {} ...", clientId);
    }
    final OAuth2Client entity = clientRepository
        .findByClientId(clientId)
        .orElseThrow(() -> new ClientRegistrationException(
            String.format("OAuth2 client [%s] was not found.", clientId)));

    final BaseClientDetails clientDetails = new BaseClientDetails();
    clientDetails.setAccessTokenValiditySeconds(entity.getAccessTokenValiditySeconds());
    clientDetails.setAdditionalInformation(entity.getAdditionalInformation());
    clientDetails.setAuthorities(roleRepository.findGrantedAuthoritiesByUserName(clientId));
    clientDetails.setAuthorizedGrantTypes(entity.getAuthorizedGrantTypes());
    clientDetails.setAutoApproveScopes(entity.getAutoApproveScopes());
    clientDetails.setClientId(entity.getClientId());
    clientDetails.setClientSecret(entity.getClientSecret());
    clientDetails.setRefreshTokenValiditySeconds(entity.getRefreshTokenValiditySeconds());
    clientDetails.setRegisteredRedirectUri(entity.getRegisteredRedirectUri());
    clientDetails.setResourceIds(entity.getResourceIds());
    clientDetails.setScope(entity.getScope());
    if (log.isDebugEnabled()) {
      log.debug("Client successfully loaded: {}", clientDetails);
    }
    return clientDetails;
  }

}
