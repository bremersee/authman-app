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

package org.bremersee.authman.business;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import org.bremersee.authman.model.UserProfileCreateRequestDto;
import org.bremersee.authman.model.UserProfileDto;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

/**
 * @author Christian Bremer
 */
public interface UserProfileService {

  UserProfileDto createUserProfile(
      @NotNull UserProfileCreateRequestDto request,
      boolean isPasswordEncrypted,
      boolean sendNotification);

  Page<UserProfileDto> getUserProfiles(String search, Pageable pageable);

  UserProfileDto getUserProfile(@NotNull String userName);

  boolean isUserProfileExisting(@NotNull String userName);

  UserProfileDto updateUserProfile(@NotNull String userName, @NotNull UserProfileDto userProfile);

  void deleteUserProfile(@NotNull String userName);

  void enableUser(@NotNull String userName, boolean isEnabled);


  boolean isPasswordPresent(@NotNull String userName);

  UserProfileDto resetPassword(@NotNull String userName, @NotBlank String newPassword);

  UserProfileDto changePassword(
      @NotNull String userName,
      String oldPassword, @NotBlank
      String newPassword);


  void changeEmail(@NotNull String userName, @NotNull String email);


  void changeMobile(@NotNull String userName, @NotNull String mobile);

}
