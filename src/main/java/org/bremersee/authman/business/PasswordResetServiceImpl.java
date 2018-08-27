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
import org.bremersee.authman.domain.PasswordResetRequest;
import org.bremersee.authman.domain.PasswordResetRequestRepository;
import org.bremersee.authman.domain.UserProfile;
import org.bremersee.authman.domain.UserProfileRepository;
import org.bremersee.authman.exception.NoEmailException;
import org.bremersee.authman.exception.NotFoundException;
import org.bremersee.authman.security.core.RoleConstants;
import org.bremersee.authman.security.core.SecurityHelper;
import org.bremersee.authman.security.core.context.RunAsCallbackWithoutResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessagePreparator;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * Password reset service implementation.
 *
 * @author Christian Bremer
 */
@Component("passwordResetService")
@Slf4j
public class PasswordResetServiceImpl implements PasswordResetService, MessageSourceAware {

  private final PasswordResetProperties properties;

  private final UserProfileRepository userProfileRepository;

  private final PasswordResetRequestRepository passwordResetRequestRepository;

  private final UserProfileService userProfileService;

  private final JavaMailSender mailSender;

  @Setter
  private MessageSource messageSource;

  @Autowired
  public PasswordResetServiceImpl(
      final PasswordResetProperties properties,
      final UserProfileRepository userProfileRepository,
      final PasswordResetRequestRepository passwordResetRequestRepository,
      final UserProfileService userProfileService,
      final JavaMailSender mailSender) {

    this.properties = properties;
    this.userProfileRepository = userProfileRepository;
    this.passwordResetRequestRepository = passwordResetRequestRepository;
    this.userProfileService = userProfileService;
    this.mailSender = mailSender;
  }

  @Override
  public void savePasswordResetRequest(@NotNull final String userNameOrEmail) {

    log.info("Saving password reset request for user [{}].", userNameOrEmail);

    final UserProfile userProfile = userProfileRepository
        .findByLogin(userNameOrEmail)
        .orElseThrow(NotFoundException::new);

    if (!StringUtils.hasText(userProfile.getEmail())) {
      log.error("Saving password reset request for user [{}]: User has no email address.",
          userProfile.getUserName());
      throw new NoEmailException();
    }

    String resetHash = UUID.randomUUID().toString();
    while (passwordResetRequestRepository.countByResetHash(resetHash) > 0) {
      resetHash = UUID.randomUUID().toString();
    }
    PasswordResetRequest entity = new PasswordResetRequest();
    entity.setEmail(userProfile.getEmail());
    entity.setResetExpiration(properties.buildExpirationDate());
    entity.setResetHash(resetHash);
    entity.setUserName(userProfile.getUserName());
    entity = passwordResetRequestRepository.save(entity);

    sendPasswordResetEmail(userProfile, entity);
  }

  private void sendPasswordResetEmail(
      final UserProfile userProfile,
      final PasswordResetRequest passwordResetRequest) {

    MimeMessagePreparator preparator = mimeMessage -> {

      final String hash = URLEncoder
          .encode(passwordResetRequest.getResetHash(), StandardCharsets.UTF_8.name());
      final String href = properties.getLink().replace("{requestHash}", hash);

      mimeMessage
          .setRecipient(Message.RecipientType.TO, new InternetAddress(userProfile.getEmail()));
      mimeMessage.setFrom(new InternetAddress(properties.getSender()));
      mimeMessage.setSubject(getSubject(userProfile));
      mimeMessage.setText("Dear " + userProfile.getDisplayName()
          + ", to reset your password please click " + href);
    };

    this.mailSender.send(preparator);
  }

  private String getSubject(final UserProfile userProfile) {
    return messageSource.getMessage(
        properties.getSubjectCode(),
        new Object[0],
        "Password Reset Request",
        LocaleUtils.toLocale(userProfile.getPreferredLocale()));
  }

  @Override
  public boolean isResetHashValid(@NotNull final String resetHash) {
    return passwordResetRequestRepository
        .countByResetHashAndResetExpirationAfter(resetHash, new Date()) > 0;
  }

  @Override
  public void processPasswordResetByHash(
      @NotNull final String resetHash,
      @NotNull final String newPassword) {

    final PasswordResetRequest request = passwordResetRequestRepository
        .findByResetHashAndResetExpirationAfter(
            resetHash, new Date()).orElseThrow(NotFoundException::new);

    SecurityHelper.runAsWithoutResult(
        request.getUserName(),
        new String[]{RoleConstants.ADMIN_ROLE, RoleConstants.USER_ROLE},
        new PasswordResetRunAsCallback(userProfileService, request, newPassword));

    passwordResetRequestRepository.delete(request);
  }

  @Scheduled(cron = "0 47 0 * * ?") // second, minute, hour, day of month, month, day(s) of week
  @Override
  public void deleteExpired() {
    log.debug("Deleting expired password reset requests ...");
    final int size = passwordResetRequestRepository.findExpiredAndRemove().size();
    log.debug("{} password reset request(s) deleted.", size);
  }

  @RequiredArgsConstructor(access = AccessLevel.PRIVATE)
  private static class PasswordResetRunAsCallback extends RunAsCallbackWithoutResult {

    @NonNull
    private final UserProfileService userProfileService;

    @NonNull
    private final PasswordResetRequest request;

    @NonNull
    private final String newPassword;

    @Override
    public void run() {
      userProfileService.changePassword(request.getUserName(), null, newPassword);
    }
  }

}
