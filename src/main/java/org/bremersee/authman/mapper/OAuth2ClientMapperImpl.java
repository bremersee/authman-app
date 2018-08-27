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

import org.apache.commons.lang3.StringUtils;
import org.bremersee.authman.domain.OAuth2Client;
import org.bremersee.authman.model.OAuth2ClientDto;
import org.springframework.stereotype.Component;

/**
 * @author Christian Bremer
 */
@Component("oauth2ClientMapper")
public class OAuth2ClientMapperImpl extends AbstractAuditMapper implements
    OAuth2ClientMapper {

  @Override
  public void mapToDto(OAuth2Client source, OAuth2ClientDto destination) {
    super.mapToDto(source, destination);
    destination.setAccessTokenValiditySeconds(source.getAccessTokenValiditySeconds());
    destination.setAuthorizedGrantTypes(source.getAuthorizedGrantTypes());
    destination.setAutoApproveScopes(source.getAutoApproveScopes());
    destination.setClientId(source.getClientId());

    destination.setClientSecretEncrypted(source.isClientSecretEncrypted());
    destination.setClientSecret(source.getClientSecret());

    destination.setDisplayName(
        StringUtils.isBlank(source.getDisplayName()) ? source.getClientId() :
            source.getDisplayName());
    destination.setRefreshTokenValiditySeconds(source.getRefreshTokenValiditySeconds());
    destination.setRegisteredRedirectUri(source.getRegisteredRedirectUri());
    destination.setResourceIds(source.getResourceIds());
    destination.setScope(source.getScope());
    destination.setAdditionalInformation(source.getAdditionalInformation());
  }

  @Override
  public OAuth2ClientDto mapToDto(OAuth2Client source) {
    OAuth2ClientDto destination = new OAuth2ClientDto();
    mapToDto(source, destination);
    return destination;
  }

  @Override
  public void updateEntity(OAuth2ClientDto source, OAuth2Client destination) {

    destination.setAccessTokenValiditySeconds(source.getAccessTokenValiditySeconds());
    destination.setAuthorizedGrantTypes(source.getAuthorizedGrantTypes());
    destination.setAutoApproveScopes(source.getAutoApproveScopes());
    destination.setDisplayName(source.getDisplayName());
    destination.setRefreshTokenValiditySeconds(source.getRefreshTokenValiditySeconds());
    destination.setRegisteredRedirectUri(source.getRegisteredRedirectUri());
    destination.setResourceIds(source.getResourceIds());
    destination.setScope(source.getScope());
    destination.setAdditionalInformation(source.getAdditionalInformation());
  }

}
