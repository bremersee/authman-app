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

package org.bremersee.authman.listener;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import javax.validation.constraints.NotNull;
import org.bremersee.authman.model.UserProfileCreateRequestDto;
import org.bremersee.authman.model.UserProfileDto;
import org.bremersee.authman.listener.model.UserProfileChangeEvent;
import org.bremersee.authman.listener.model.UserProfileCreationEvent;
import org.bremersee.authman.listener.model.UserProfileRegistrationRequestEvent;

/**
 * @author Christian Bremer
 */
public class UserProfileListenerMapperImpl implements UserProfileListenerMapper {

  @Override
  public UserProfileRegistrationRequestEvent mapToRegistrationRequestEvent(
      @NotNull UserProfileCreateRequestDto request, @NotNull Date expirationDate) {

    final UserProfileRegistrationRequestEvent dto = new UserProfileRegistrationRequestEvent();
    dto.setUserName(request.getUserName());
    dto.setPassword(request.getPassword());
    dto.setDisplayName(request.getDisplayName());
    dto.setEmail(request.getEmail());
    dto.setPreferredLocale(request.getPreferredLocale());
    dto.setPreferredTimeZoneId(request.getPreferredTimeZoneId());

    dto.setExpirationDate(OffsetDateTime.ofInstant(expirationDate.toInstant(), ZoneOffset.UTC));
    return dto;
  }

  @Override
  public UserProfileCreationEvent mapToCreationEvent(@NotNull UserProfileDto userProfile,
      String password, @NotNull Collection<String> roles) {

    final UserProfileCreationEvent dto = new UserProfileCreationEvent();

    dto.setId(userProfile.getId());
    if (userProfile.getCreated() != null) {
      dto.setCreated(OffsetDateTime.ofInstant(userProfile.getCreated().toInstant(),
          ZoneOffset.UTC));
    }
    dto.setCreatedBy(userProfile.getCreatedBy());
    if (userProfile.getModified() != null) {
      dto.setModified(OffsetDateTime.ofInstant(userProfile.getModified().toInstant(),
          ZoneOffset.UTC));
    }
    dto.setModifiedBy(userProfile.getModifiedBy());

    dto.setUserName(userProfile.getUserName());
    dto.setDisplayName(userProfile.getDisplayName());
    dto.setEmail(userProfile.getEmail());
    dto.setMobile(userProfile.getMobile());
    dto.setPreferredLocale(userProfile.getPreferredLocale());
    dto.setPreferredTimeZoneId(userProfile.getPreferredTimeZoneId());
    if (userProfile.getSambaSettings() != null
        && userProfile.getSambaSettings().getSambaGroups() != null) {
      dto.setGroups(userProfile.getSambaSettings().getSambaGroups());
    }

    dto.setPassword(password);

    dto.setRoles(new ArrayList<>(roles));

    return dto;
  }

  @Override
  public UserProfileChangeEvent mapToChangeEvent(@NotNull UserProfileDto userProfile) {

    final UserProfileChangeEvent dto = new UserProfileChangeEvent();

    dto.setId(userProfile.getId());
    if (userProfile.getCreated() != null) {
      dto.setCreated(OffsetDateTime.ofInstant(userProfile.getCreated().toInstant(),
          ZoneOffset.UTC));
    }
    dto.setCreatedBy(userProfile.getCreatedBy());
    if (userProfile.getModified() != null) {
      dto.setModified(OffsetDateTime.ofInstant(userProfile.getModified().toInstant(),
          ZoneOffset.UTC));
    }
    dto.setModifiedBy(userProfile.getModifiedBy());

    dto.setUserName(userProfile.getUserName());
    dto.setDisplayName(userProfile.getDisplayName());
    dto.setEmail(userProfile.getEmail());
    dto.setMobile(userProfile.getMobile());
    dto.setPreferredLocale(userProfile.getPreferredLocale());
    dto.setPreferredTimeZoneId(userProfile.getPreferredTimeZoneId());
    if (userProfile.getSambaSettings() != null
        && userProfile.getSambaSettings().getSambaGroups() != null) {
      dto.setGroups(userProfile.getSambaSettings().getSambaGroups());
    }

    return dto;
  }
}
