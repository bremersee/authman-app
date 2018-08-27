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

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.UUID;
import javax.mail.Message;
import javax.mail.internet.InternetAddress;
import javax.validation.constraints.NotNull;
import lombok.AccessLevel;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.LocaleUtils;
import org.bremersee.authman.domain.EmailChangeRequest;
import org.bremersee.authman.domain.EmailChangeRequestRepository;
import org.bremersee.authman.domain.UserProfile;
import org.bremersee.authman.domain.UserProfileRepository;
import org.bremersee.authman.exception.EmailAlreadyExistsException;
import org.bremersee.authman.exception.InvalidEmailException;
import org.bremersee.authman.exception.NotFoundException;
import org.bremersee.authman.security.core.RoleConstants;
import org.bremersee.authman.security.core.SecurityHelper;
import org.bremersee.authman.security.core.context.RunAsCallbackWithoutResult;
import org.bremersee.authman.validation.ValidationProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessagePreparator;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * @author Christian Bremer
 */
@Component("emailChangeService")
@Slf4j
public class EmailChangeServiceImpl implements EmailChangeService, MessageSourceAware {

  private final ValidationProperties validationProperties;

  private final EmailChangeProperties emailChangeProperties;

  private final EmailChangeRequestRepository changeRequestRepository;

  private final UserProfileRepository userProfileRepository;

  private final UserProfileService userProfileService;

  private final JavaMailSender mailSender;

  @Setter
  private MessageSource messageSource;

  @Autowired
  public EmailChangeServiceImpl(
      final ValidationProperties validationProperties,
      final EmailChangeProperties emailChangeProperties,
      final EmailChangeRequestRepository changeRequestRepository,
      final UserProfileRepository userProfileRepository,
      final UserProfileService userProfileService,
      final JavaMailSender mailSender) {

    this.validationProperties = validationProperties;
    this.emailChangeProperties = emailChangeProperties;
    this.changeRequestRepository = changeRequestRepository;
    this.userProfileRepository = userProfileRepository;
    this.userProfileService = userProfileService;
    this.mailSender = mailSender;
  }

  @PreAuthorize("hasRole('ROLE_ADMIN') or authentication.name == #userName")
  @Override
  public void saveEmailChangeRequest(
      @NotNull final String userName,
      final String newEmail) {

    log.info("Saving email change request of user [{}] and new email [{}].", userName, newEmail);

    if (!StringUtils.hasText(newEmail)
        || !validationProperties.getEmailPattern().matcher(newEmail).matches()) {
      throw new InvalidEmailException(newEmail);
    }

    if (userProfileRepository.countByEmail(newEmail) > 0) {
      throw new EmailAlreadyExistsException(newEmail);
    }

    final UserProfile userProfile = userProfileRepository
        .findByUserName(userName).orElseThrow(NotFoundException::new);

    String hash = UUID.randomUUID().toString();
    while (changeRequestRepository.countByChangeHash(hash) > 0) {
      hash = UUID.randomUUID().toString();
    }

    EmailChangeRequest request = new EmailChangeRequest();
    request.setChangeExpiration(emailChangeProperties.buildExpirationDate());
    request.setChangeHash(hash);
    request.setNewEmail(newEmail);
    request.setUserName(userName);

    request = changeRequestRepository.save(request);

    sendConfirmEmail(userProfile, request);
  }

  private void sendConfirmEmail(
      final UserProfile userProfile,
      final EmailChangeRequest request) {

    MimeMessagePreparator preparator = mimeMessage -> {

      final String hash = URLEncoder
          .encode(request.getChangeHash(), StandardCharsets.UTF_8.name());
      final String href = emailChangeProperties.getLink().replace("{requestHash}", hash);

      mimeMessage
          .setRecipient(Message.RecipientType.TO, new InternetAddress(userProfile.getEmail()));
      mimeMessage.setFrom(new InternetAddress(emailChangeProperties.getSender()));
      mimeMessage.setSubject(getSubject(userProfile));
      mimeMessage.setText("Dear " + userProfile.getDisplayName()
          + ", to change your email please click " + href);
    };

    this.mailSender.send(preparator);
  }

  private String getSubject(final UserProfile userProfile) {
    return messageSource.getMessage(
        emailChangeProperties.getSubjectCode(),
        new Object[0],
        "Email Change Request",
        LocaleUtils.toLocale(userProfile.getPreferredLocale()));
  }

  @Override
  public void processEmailChangeByHash(@NotNull final String hash) {
    log.info("Processing email change request with hash [{}].", hash);
    EmailChangeRequest request = changeRequestRepository
        .findByChangeHashAndChangeExpirationAfter(hash, new Date())
        .orElseThrow(NotFoundException::new);
    SecurityHelper.runAsWithoutResult(
        request.getUserName(),
        new String[]{RoleConstants.USER_ROLE},
        new EmailChangeRunAsCallback(userProfileService, request));
    changeRequestRepository.delete(request);
  }

  @Scheduled(cron = "0 37 0 * * ?") // second, minute, hour, day of month, month, day(s) of week
  @Override
  public void deleteExpired() {
    log.debug("Deleting expired email change requests ...");
    final int size = changeRequestRepository.findExpiredAndRemove().size();
    log.debug("{} email change request(s) deleted.", size);
  }

  @RequiredArgsConstructor(access = AccessLevel.PRIVATE)
  private static class EmailChangeRunAsCallback extends RunAsCallbackWithoutResult {

    @NonNull
    private final UserProfileService userProfileService;

    @NonNull
    private final EmailChangeRequest request;

    @Override
    public void run() {
      userProfileService.changeEmail(request.getUserName(), request.getNewEmail());
    }
  }

}
