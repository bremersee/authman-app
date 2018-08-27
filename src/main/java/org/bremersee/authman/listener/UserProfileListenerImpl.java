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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.bremersee.authman.model.UserProfileCreateRequestDto;
import org.bremersee.authman.model.UserProfileDto;
import org.bremersee.authman.listener.api.UserProfileListenerApi;
import org.bremersee.authman.listener.model.Enabled;
import org.bremersee.authman.listener.model.NewEmail;
import org.bremersee.authman.listener.model.NewMobile;
import org.bremersee.authman.listener.model.NewPassword;
import org.bremersee.authman.listener.model.NewRoles;
import org.bremersee.authman.listener.model.UserProfileChangeEvent;
import org.bremersee.authman.listener.model.UserProfileCreationEvent;
import org.bremersee.authman.listener.model.UserProfileRegistrationRequestEvent;
import org.springframework.scheduling.annotation.Async;

/**
 * @author Christian Bremer
 */
@Slf4j
public class UserProfileListenerImpl implements UserProfileListener {

  @Setter
  private UserProfileListenerMapper mapper = new UserProfileListenerMapperImpl();

  @Getter
  private List<UserProfileListenerApi> httpListeners = new ArrayList<>();

  @Async
  @Override
  public void onUserRegistrationRequest(
      @NotNull UserProfileCreateRequestDto request,
      @NotNull Date expirationDate) {

    final UserProfileRegistrationRequestEvent dto = mapper.mapToRegistrationRequestEvent(
        request, expirationDate);
    httpListeners.forEach(listener -> {
      try {
        listener.onUserRegistrationRequest(dto);

      } catch (final RuntimeException re) {
        log.error(
            "Publishing registration event [" + dto
                + "] failed with listener [" + listener + "].", re);// NOSONAR
      }
    });
  }

  @Async
  @Override
  public void onCreateUserProfile(
      @NotNull UserProfileDto userProfile,
      String password,
      @NotNull Collection<String> roles) {

    final UserProfileCreationEvent dto = mapper.mapToCreationEvent(userProfile, password, roles);
    httpListeners.forEach(listener -> {
      try {
        listener.onCreateUserProfile(dto);

      } catch (final RuntimeException re) {
        log.error("Publishing create event [" + dto + "] failed with listener [" + listener + "].",
            re);
      }
    });
  }

  @Async
  @Override
  public void onChangeUserProfile(@NotNull UserProfileDto userProfile) {

    final UserProfileChangeEvent dto = mapper.mapToChangeEvent(userProfile);
    httpListeners.forEach(listener -> {
      try {
        listener.onChangeUserProfile(dto);

      } catch (final RuntimeException re) {
        log.error("Publishing change event [" + dto + "] failed with listener [" + listener + "].",
            re);
      }
    });
  }

  @Async
  @Override
  public void onDeleteUserProfile(@NotBlank final String userName) {

    httpListeners.forEach(listener -> {
      try {
        listener.onDeleteUserProfile(userName);

      } catch (final RuntimeException re) {
        log.error(
            "Publishing delete event of user profile [" + userName + "] failed with listener ["
                + listener + "].", re);
      }
    });
  }

  @Async
  @Override
  public void onChangeEnabledState(@NotBlank final String userName, final boolean enabled) {

    final Enabled dto = new Enabled();
    dto.setValue(enabled);
    httpListeners.forEach(listener -> {
      try {
        listener.onChangeEnabledState(userName, dto);

      } catch (final RuntimeException re) {
        log.error("Publishing new enabled state [" + enabled + "] of user profile [" // NOSONAR
            + userName + "] failed with listener [" + listener + "].", re);
      }
    });
  }

  @Async
  @Override
  public void onNewPassword(@NotBlank final String userName, final String newPassword) {

    final NewPassword dto = new NewPassword();
    dto.setValue(newPassword);
    httpListeners.forEach(listener -> {
      try {
        listener.onNewPassword(userName, dto);

      } catch (final RuntimeException re) {
        log.error(
            "Publishing new password of user profile [" + userName + "] failed with listener ["
                + listener + "].", re);
      }
    });
  }

  @Async
  @Override
  public void onNewEmail(@NotBlank final String userName, @NotBlank final String newEmail) {

    final NewEmail dto = new NewEmail();
    dto.setValue(newEmail);
    httpListeners.forEach(listener -> {
      try {
        listener.onNewEmail(userName, dto);

      } catch (final RuntimeException re) {
        log.error("Publishing new email [" + newEmail + "] of user profile [" + userName
            + "] failed with listener [" + listener + "].", re);
      }
    });
  }

  @Async
  @Override
  public void onNewMobile(@NotBlank final String userName, @NotBlank final String newMobile) {

    final NewMobile dto = new NewMobile();
    dto.setValue(newMobile);
    httpListeners.forEach(listener -> {
      try {
        listener.onNewMobile(userName, dto);

      } catch (final RuntimeException re) {
        log.error("Publishing new mobile number [" + newMobile + "] of user profile [" + userName
            + "] failed with listener [" + listener + "].", re);
      }
    });
  }

  @Async
  @Override
  public void onDeleteMobile(@NotBlank final String userName, final String number) {

    httpListeners.forEach(listener -> {
      try {
        listener.onDeleteMobile(userName, number);

      } catch (final RuntimeException re) {
        log.error(
            "Publishing deletion of mobile number [" + number + "] of user profile [" + userName
                + "] failed with listener [" + listener + "].", re);
      }
    });
  }

  @Async
  @Override
  public void onNewRoles(
      @NotBlank final String userName,
      @NotNull final Collection<String> newRoles) {

    final NewRoles dto = new NewRoles();
    dto.setRoles(new ArrayList<>(newRoles));
    httpListeners.forEach(listener -> {
      try {
        listener.onNewRoles(userName, dto);

      } catch (final RuntimeException re) {
        log.error("Publishing new mobile number roles of user profile [" + userName
            + "] failed with listener [" + listener + "].", re);
      }
    });
  }
}
