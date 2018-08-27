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

import java.util.Locale;
import org.bremersee.authman.domain.OAuth2Scope;
import org.bremersee.authman.model.OAuth2ScopeDto;
import org.springframework.stereotype.Component;

/**
 * @author Christian Bremer
 */
@Component("oauth2ScopeMapper")
public class OAuth2ScopeMapperImpl extends AbstractAuditMapper implements
    OAuth2ScopeMapper {

  @Override
  public OAuth2ScopeDto mapToDto(final OAuth2Scope source, final Locale locale) {

    OAuth2ScopeDto destination = new OAuth2ScopeDto();
    mapToDto(source, destination, locale);
    return destination;
  }

  @Override
  public void mapToDto(final OAuth2Scope source, final OAuth2ScopeDto destination,
      final Locale locale) {

    final String lang = locale != null ? locale.getLanguage() : source.getDefaultLanguage();
    super.mapToDto(source, destination);
    destination.setScope(source.getScope());
    String description = source.getDescriptions().get(lang);
    if (description == null) {
      description = source.getDescriptions().get(source.getDefaultLanguage());
    }
    destination.setDescription(description);

    destination.setDefaultLanguage(source.getDefaultLanguage());
    destination.getDescriptions().clear();
    destination.getDescriptions().putAll(source.getDescriptions());
    destination.setVisibility(source.getVisibility());
  }

  @Override
  public void updateEntity(OAuth2ScopeDto source, OAuth2Scope destination) {
    destination.setScope(source.getScope());
    destination.setDefaultLanguage(source.getDefaultLanguage());
    destination.getDescriptions().clear();
    if (source.getDescriptions() != null) {
      destination.getDescriptions().putAll(source.getDescriptions());
    }
    destination.setVisibility(source.getVisibility());
  }

}
