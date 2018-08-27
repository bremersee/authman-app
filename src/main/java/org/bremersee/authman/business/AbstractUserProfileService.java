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

package org.bremersee.authman.business;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.TimeZone;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.LocaleUtils;
import org.bremersee.authman.domain.UserProfileRepository;
import org.bremersee.authman.exception.EmailAlreadyExistsException;
import org.bremersee.authman.exception.InvalidEmailException;
import org.bremersee.authman.exception.InvalidLocaleException;
import org.bremersee.authman.exception.InvalidTimeZoneException;
import org.bremersee.authman.exception.InvalidUserNameException;
import org.bremersee.authman.exception.PasswordTooWeakException;
import org.bremersee.authman.exception.UserNameAlreadyExistsException;
import org.bremersee.authman.model.UserProfileCreateRequestDto;
import org.bremersee.authman.validation.ValidationProperties;
import org.springframework.util.StringUtils;

/**
 * @author Christian Bremer
 */
@Slf4j
public class AbstractUserProfileService {

  private static final Set<String> TIME_ZONE_IDS = new HashSet<>(
      Arrays.asList(TimeZone.getAvailableIDs()));

  @Getter(AccessLevel.PACKAGE)
  private final ValidationProperties validationProperties;

  @Getter(AccessLevel.PACKAGE)
  private final UserProfileRepository userRepository;

  public AbstractUserProfileService(
      ValidationProperties validationProperties,
      UserProfileRepository userRepository) {

    this.validationProperties = validationProperties;
    this.userRepository = userRepository;
  }

  void validateUserProfileCreateRequest(final UserProfileCreateRequestDto request) {

    if (!StringUtils.hasText(request.getUserName())
        || !validationProperties.getUserNameExactPattern().matcher(request.getUserName())
        .matches()) {
      log.error("User name is invalid: {}", request.getUserName());
      throw new InvalidUserNameException(request.getUserName());
    }
    if (userRepository.countByUserName(request.getUserName()) > 0) {
      log.error("User name already exists: {}", request.getUserName());
      throw new UserNameAlreadyExistsException(request.getUserName());
    }

    validatePassword(request.getPassword());
    validateEmail(request.getEmail());
    validatePreferredLocale(request.getPreferredLocale());
    validatePreferredTimeZone(request.getPreferredTimeZoneId());
  }

  void validateEmail(String email) {
    if (!StringUtils.hasText(email)
        || !validationProperties.getEmailPattern().matcher(email).matches()) {
      log.error("Email is invalid: {}", email);
      throw new InvalidEmailException(email);
    }
    if (userRepository.countByEmail(email) > 0) {
      log.error("Email already exists: {}", email);
      throw new EmailAlreadyExistsException(email);
    }
  }

  void validatePreferredLocale(String preferredLocale) {
    if (!StringUtils.hasText(preferredLocale)) {
      log.error("Locale is empty.");
      throw new InvalidLocaleException();
    } else {
      try {
        LocaleUtils.toLocale(preferredLocale);

      } catch (RuntimeException re) {
        log.error("Locale is invalid: {}", preferredLocale);
        throw new InvalidLocaleException(preferredLocale);
      }
    }
  }

  void validatePreferredTimeZone(String preferredTimeZone) {
    if (!StringUtils.hasText(preferredTimeZone)) {
      log.error("Preferred time zone is required.");
      throw new InvalidTimeZoneException();
    } else if (!TIME_ZONE_IDS.contains(preferredTimeZone)) {
      log.error("Preferred time zone is invalid.");
      throw new InvalidTimeZoneException(preferredTimeZone);
    }
  }

  void validatePassword(final String password) {
    if (!StringUtils.hasText(password)
        || !validationProperties.getPasswordPattern().matcher(password).matches()) {
      log.error("Password is too weak.");
      throw new PasswordTooWeakException();
    }
  }

}
