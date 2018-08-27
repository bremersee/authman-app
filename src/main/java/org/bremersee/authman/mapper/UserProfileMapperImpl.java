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

import javax.validation.constraints.NotNull;
import org.bremersee.authman.domain.UserProfile;
import org.bremersee.authman.model.UserProfileDto;
import org.bremersee.authman.security.core.SecurityHelper;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * @author Christian Bremer
 */
@Component("userProfileMapper")
public class UserProfileMapperImpl extends AbstractAuditMapper implements UserProfileMapper {

  @Override
  public void mapToDto(
      @NotNull final UserProfile source,
      @NotNull final UserProfileDto destination) {

    super.mapToDto(source, destination);
    destination.setUserName(source.getUserName());
    destination.setEnabled(source.isEnabled());
    destination.setDisplayName(source.getDisplayName());
    destination.setPreferredLocale(source.getPreferredLocale());
    destination.setPreferredTimeZoneId(source.getPreferredTimeZoneId());
    destination.setEmail(source.getEmail());
    destination.setMobile(source.getMobile());
    destination.setSambaSettings(source.getSambaSettings());
  }

  @Override
  public UserProfileDto mapToDto(@NotNull final UserProfile source) {

    final UserProfileDto destination = new UserProfileDto();
    mapToDto(source, destination);
    return destination;
  }

  @Override
  public void updateEntity(
      @NotNull final UserProfileDto source,
      @NotNull final UserProfile destination) {

    if (StringUtils.hasText(source.getDisplayName())) {
      destination.setDisplayName(source.getDisplayName());
    }
    if (StringUtils.hasText(source.getPreferredLocale())) {
      destination.setPreferredLocale(source.getPreferredLocale());
    }
    if (StringUtils.hasText(source.getPreferredTimeZoneId())) {
      destination.setPreferredTimeZoneId(source.getPreferredTimeZoneId());
    }
    if (SecurityHelper.isCurrentUserAdmin()) {
      destination.setEnabled(source.isEnabled());
      destination.setSambaSettings(source.getSambaSettings());
      if (StringUtils.hasText(source.getEmail())) {
        destination.setEmail(source.getEmail());
      } else {
        destination.setEmail(null);
      }
      if (StringUtils.hasText(source.getMobile())) {
        destination.setMobile(source.getMobile());
      } else {
        destination.setMobile(null);
      }
    }
  }
}
