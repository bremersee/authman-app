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

import java.util.Date;
import javax.validation.constraints.NotNull;
import lombok.AccessLevel;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.LocaleUtils;
import org.bremersee.authman.domain.MobileChangeRequest;
import org.bremersee.authman.domain.MobileChangeRequestRepository;
import org.bremersee.authman.domain.UserProfile;
import org.bremersee.authman.domain.UserProfileRepository;
import org.bremersee.authman.exception.InvalidMobileException;
import org.bremersee.authman.exception.NotFoundException;
import org.bremersee.authman.exception.SmsSendException;
import org.bremersee.authman.security.core.RoleConstants;
import org.bremersee.authman.security.core.SecurityHelper;
import org.bremersee.authman.security.core.context.RunAsCallbackWithoutResult;
import org.bremersee.authman.validation.ValidationProperties;
import org.bremersee.sms.SmsException;
import org.bremersee.sms.SmsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * @author Christian Bremer
 */
@Component("mobileChangeService")
@Slf4j
public class MobileChangeServiceImpl implements MobileChangeService, MessageSourceAware {

  private final ValidationProperties validationProperties;

  private final MobileChangeProperties mobileChangeProperties;

  private final MobileChangeRequestRepository changeRequestRepository;

  private final UserProfileRepository userProfileRepository;

  private final UserProfileService userProfileService;

  private final SmsService smsService;

  @Setter
  private MessageSource messageSource;

  @Autowired
  public MobileChangeServiceImpl(
      final ValidationProperties validationProperties,
      final MobileChangeProperties mobileChangeProperties,
      final MobileChangeRequestRepository changeRequestRepository,
      final UserProfileRepository userProfileRepository,
      final UserProfileService userProfileService,
      final SmsService smsService) {

    this.validationProperties = validationProperties;
    this.mobileChangeProperties = mobileChangeProperties;
    this.changeRequestRepository = changeRequestRepository;
    this.userProfileRepository = userProfileRepository;
    this.userProfileService = userProfileService;
    this.smsService = smsService;
  }

  @PreAuthorize("hasRole('ROLE_ADMIN') or authentication.name == #userName")
  @Override
  public void saveMobileChangeRequest(@NotNull String userName, String newMobile) {
    log.info("Saving mobile change request of user [{}] and new mobile [{}].", userName, newMobile);
    if (!StringUtils.hasText(newMobile)
        || !validationProperties.getMobilePattern().matcher(newMobile).matches()) {
      throw new InvalidMobileException(newMobile);
    }
    final UserProfile userProfile = userProfileRepository
        .findByUserName(userName)
        .orElseThrow(NotFoundException::new);
    String hash = newHash();
    while (changeRequestRepository.countByChangeHash(hash) > 0) {
      hash = newHash();
    }
    MobileChangeRequest request = new MobileChangeRequest();
    request.setChangeExpiration(mobileChangeProperties.buildExpirationDate());
    request.setChangeHash(hash);
    request.setNewMobile(newMobile);
    request.setUserName(userName);
    request = changeRequestRepository.save(request);
    sendSms(userProfile, request);
  }

  private String newHash() {
    int len = mobileChangeProperties.getHashLength();
    if (len < 4) {
      len = 4;
    } else if (len > 10) {
      len = 10;
    }
    String hash = String.valueOf((long) (Math.random() * Long.MAX_VALUE));
    while (hash.length() < len + 1) {
      hash = String.valueOf((long) (Math.random() * Long.MAX_VALUE));
    }
    return hash.substring(1, len + 1);
  }

  private void sendSms(UserProfile userProfile, MobileChangeRequest request) {
    final Object[] params = new Object[1];
    params[0] = request.getChangeHash();
    final String defaultMessage = "The confirmation code of your new mobile number is "
        + request.getChangeHash();
    final String message = messageSource.getMessage(
        "mobile.change.sms.message",
        params, defaultMessage,
        LocaleUtils.toLocale(userProfile.getPreferredLocale()));
    try {
      smsService.sendSms(request.getNewMobile(), message);

    } catch (SmsException e) {
      log.error("Sending mobile change SMS to [{}] of user [{}] failed.",
          request.getNewMobile(), request.getUserName(), e);
      throw new SmsSendException(e);
    }
  }

  @Override
  public void processMobileChangeByHash(@NotNull final String hash) {
    log.info("Processing mobile change request with hash [{}].", hash);
    MobileChangeRequest request = changeRequestRepository
        .findByChangeHashAndChangeExpirationAfter(hash, new Date())
        .orElseThrow(NotFoundException::new);
    SecurityHelper.runAsWithoutResult(
        request.getUserName(),
        new String[]{RoleConstants.USER_ROLE},
        new MobileChangeRunAsCallback(userProfileService, request));
    changeRequestRepository.delete(request);
  }

  @Scheduled(cron = "0 27 0 * * ?") // second, minute, hour, day of month, month, day(s) of week
  @Override
  public void deleteExpired() {
    log.debug("Deleting expired email change requests ...");
    final int size = changeRequestRepository.findExpiredAndRemove().size();
    log.debug("{} email change request(s) deleted.", size);
  }

  @RequiredArgsConstructor(access = AccessLevel.PRIVATE)
  private static class MobileChangeRunAsCallback extends RunAsCallbackWithoutResult {

    @NonNull
    private final UserProfileService userProfileService;

    @NonNull
    private final MobileChangeRequest request;

    @Override
    public void run() {
      userProfileService.changeMobile(request.getUserName(), request.getNewMobile());
    }
  }

}
