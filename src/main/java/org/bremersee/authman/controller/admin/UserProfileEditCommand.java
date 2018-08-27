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

package org.bremersee.authman.controller.admin;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import javax.validation.constraints.NotNull;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.bremersee.authman.model.SambaSettingsDto;
import org.bremersee.authman.model.UserProfileDto;

/**
 * @author Christian Bremer
 */
@Getter
@Setter
@ToString(callSuper = true)
@EqualsAndHashCode(callSuper = true)
@NoArgsConstructor
public class UserProfileEditCommand extends UserProfileDto {

  private static final long serialVersionUID = -261741512443428507L;

  private boolean sambaActivated = false;

  private List<String> roles = new ArrayList<>();

  public UserProfileEditCommand(
      @NotNull final UserProfileDto user,
      @NotNull final Collection<String> roles) {

    setCreated(user.getCreated());
    setCreatedBy(user.getCreatedBy());
    setDisplayName(user.getDisplayName());
    setEmail(user.getEmail());
    setEnabled(user.isEnabled());
    setId(user.getId());
    setMobile(user.getMobile());
    setModified(user.getModified());
    setModifiedBy(user.getModifiedBy());
    setPreferredLocale(user.getPreferredLocale());
    setPreferredTimeZoneId(user.getPreferredTimeZoneId());
    setUserName(user.getUserName());
    setVersion(user.getVersion());

    if (user.getSambaSettings() == null) {
      this.sambaActivated = false;
      setSambaSettings(new SambaSettingsDto());
    } else {
      this.sambaActivated = true;
      setSambaSettings(user.getSambaSettings());
    }

    this.roles.addAll(roles);
  }
}

