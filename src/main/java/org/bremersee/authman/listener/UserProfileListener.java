/*
 * Copyright 2016 the original author or authors.
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

import java.util.Collection;
import java.util.Date;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import org.bremersee.authman.model.UserProfileCreateRequestDto;
import org.bremersee.authman.model.UserProfileDto;

/**
 * @author Christian Bremer
 */
public interface UserProfileListener {

  /**
   * Publish the user registration request.
   *
   * @param request        the registration request
   * @param expirationDate the expiration date of the request
   */
  void onUserRegistrationRequest(
      @NotNull UserProfileCreateRequestDto request,
      @NotNull Date expirationDate);

  /**
   * Publish the user creation event.
   *
   * @param userProfile the user profile
   * @param password    the clear password or {@code null} if there is no clear password
   */
  void onCreateUserProfile(
      @NotNull UserProfileDto userProfile,
      String password,
      @NotNull Collection<String> roles);

  void onChangeUserProfile(@NotNull UserProfileDto userProfile);

  void onDeleteUserProfile(@NotBlank String userName);

  void onChangeEnabledState(@NotBlank String userName, boolean enabled);

  void onNewPassword(@NotBlank String userName, String newPassword);

  void onNewEmail(@NotBlank String userName, @NotBlank String newEmail);

  void onNewMobile(@NotBlank String userName, @NotBlank String newMobile);

  void onDeleteMobile(@NotBlank String userName, String number);

  void onNewRoles(@NotBlank String userName, @NotNull Collection<String> newRoles);

}
